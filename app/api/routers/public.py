import asyncio
import hashlib

from fastapi import APIRouter, HTTPException, Request, Response, status
from langchain_core.messages import AIMessage, HumanMessage

from app.agent.graph.public_chat import get_public_chat_graph
from app.agent.llm.public_client import PublicChatConfigError
from app.agent.public_limits import (
    CHAT_SLOT_WAIT_SECONDS,
    chat_slots,
    daily_counter,
)
from app.agent.states import new_chat_state
from app.api.deps import CurrentGuest
from app.core.auth import AuthConfigError, create_guest_token
from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.public_chat import (
    MAX_HISTORY_TOTAL_CHARS,
    GuestToken,
    PublicChatReply,
    PublicChatRequest,
)
from app.security.client_ip import identify
from app.security.rate_limit import (
    use_visitor_quota,
    visitor_quota_left,
    visitor_token_limiter,
)

logger = get_logger("api.public")

# Everything here is for anonymous visitors of the public demo. This module
# never imports the admin chat graph (get_chat_graph): a visitor's request
# can only ever reach the public graph, whatever path is guessed.
router = APIRouter(prefix="/public", tags=["public"])

RUN_TIMEOUT_SECONDS = 90.0


def not_found() -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


def ensure_enabled() -> None:
    # Switched off, the public endpoints do not exist.
    if not get_settings().public_chat:
        raise not_found()


def limited(detail: str, wait: int) -> HTTPException:
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        detail,
        headers={"Retry-After": str(wait)},
    )


@router.post("/visitors", response_model=GuestToken)
def new_visitor(request: Request) -> GuestToken:
    # No body, no password, no credentials: it hands out a guest token for
    # the public chat. A token proves nothing about who asks; what protects
    # the demo is the per-visitor message limit (by real IP) and the global
    # budgets, so a new token never means more messages.
    ensure_enabled()
    visitor = identify(request)
    wait = visitor_token_limiter().hit(visitor.key)

    if wait > 0:
        raise limited("Too many guest sessions. Try again later.", wait)

    try:
        token, seconds = create_guest_token()

    except AuthConfigError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Sign-in is unavailable"
        ) from None

    return GuestToken(access_token=token, expires_in=seconds)


def build_messages(body: PublicChatRequest, max_chars: int) -> list:
    if len(body.message) > max_chars:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Message too long: {max_chars} characters at most.",
        )

    history = body.history
    total = sum(len(item.content) for item in history) + len(body.message)

    if total > MAX_HISTORY_TOTAL_CHARS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "The conversation is too long."
        )

    for item in history:
        if item.role == "user" and len(item.content) > max_chars:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"Message too long: {max_chars} characters at most.",
            )

    messages = [
        HumanMessage(content=item.content)
        if item.role == "user"
        else AIMessage(content=item.content)
        for item in history
    ]
    messages.append(HumanMessage(content=body.message))

    return messages


@router.post("/chat", response_model=PublicChatReply)
async def public_chat(
    body: PublicChatRequest,
    request: Request,
    response: Response,
    guest: CurrentGuest,
) -> PublicChatReply:
    ensure_enabled()
    settings = get_settings()
    messages = build_messages(body, settings.public_chat_message_chars)
    visitor = identify(request)

    # The limit counts the real visitor, not the token: a new token does not
    # reset it. Refused requests never touch the global daily counter.
    wait = use_visitor_quota(visitor)

    if wait > 0:
        raise limited("Too many messages. Try again later.", wait)

    if not daily_counter().take():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The demo has reached its limit for today. Please come back "
            "tomorrow.",
        )

    slots = chat_slots()

    try:
        await asyncio.wait_for(slots.acquire(), timeout=CHAT_SLOT_WAIT_SECONDS)

    except asyncio.TimeoutError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The demo is busy. Try again in a moment.",
        ) from None

    try:
        graph = get_public_chat_graph()
        state = new_chat_state(guest.subject, messages)
        result = await asyncio.wait_for(
            graph.ainvoke(state, config={"recursion_limit": 30}),
            timeout=RUN_TIMEOUT_SECONDS,
        )

    except PublicChatConfigError:
        logger.error("the public chat model is not configured")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "The demo is unavailable."
        ) from None

    except asyncio.TimeoutError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "The answer took too long."
        ) from None

    except Exception as exc:
        logger.error("public chat failed: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "The demo is unavailable."
        ) from None

    finally:
        slots.release()

    left = visitor_quota_left(visitor)
    response.headers["X-RateLimit-Remaining"] = str(left)
    logger.info(
        "public chat answered",
        extra={
            "visitor": hashlib.sha256(visitor.key.encode()).hexdigest()[:8],
            "turns": result.get("tool_turns", 0),
        },
    )

    return PublicChatReply(reply=result["reply"], remaining=left)
