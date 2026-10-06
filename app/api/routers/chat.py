from collections.abc import AsyncIterator, Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from app.agent.graph.chat import get_chat_graph
from app.agent.llm.agithar_client import AgentConfigError
from app.api.deps import CurrentUser, Registry
from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.rate_limit import UsageLimiter, too_many_messages
from app.schemas.chat import (
    ChatReply,
    ChatRequest,
    ChatSession,
    ChatSessionList,
)
from app.services import chat_service
from app.services.chat_service import ChatFailedError
from app.services.chat_store import (
    ChatStore,
    SessionLimitError,
    SessionNotFoundError,
    get_chat_store,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
SSE_MEDIA_TYPE = "text/event-stream"
# nginx must not buffer the stream or the tokens arrive all at once.
SSE_HEADERS = {"X-Accel-Buffering": "no"}
CHAT_WINDOW_SECONDS = 60

logger = get_logger("api.chat")

router = APIRouter(prefix="/chat", tags=["chat"])

Store = Annotated[ChatStore, Depends(get_chat_store)]
Skip = Annotated[int, Query(ge=0)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]
SessionId = Annotated[
    str, Path(min_length=1,
              max_length=64,
              pattern=r"^[A-Za-z0-9_-]+$")
]


def session_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Session not found"
    )


def session_limit() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many chat sessions",
    )


@lru_cache
def chat_limiter() -> UsageLimiter:
    return UsageLimiter(
        get_settings().chat_rate_limit_per_minute, 
        CHAT_WINDOW_SECONDS
    )


def ensure_chat_allowed(user_id: int) -> None:
    wait = chat_limiter().hit(str(user_id))

    if wait > 0:
        raise too_many_messages(wait)


def chat_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Chat is unavailable",
    )


def build_graph():
    # Built on the first admin message: a missing Claude key then affects
    # only the LLM chat, never the sensor-only reply of the other users.
    try:
        return get_chat_graph()

    except AgentConfigError:
        logger.error("chat graph needs the anthropic api key")
        raise chat_unavailable() from None


def open_chat_session(
    store: ChatStore,
    user_id: int, 
    request: ChatRequest
) -> ChatSession:
    try:
        return chat_service.open_session(store, user_id, request)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc

    except SessionLimitError as exc:
        raise session_limit() from exc


def run_chat(
    store: ChatStore,
    registry: Registry,
    user_id: int,
    request: ChatRequest,
) -> ChatReply:
    try:
        return chat_service.respond(store,
                                    registry, 
                                    user_id, request)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc

    except SessionLimitError as exc:
        raise session_limit() from exc


def sse_event(event) -> str:
    return f"data: {event.model_dump_json(exclude_none=True)}\n\n"


def sse_lines(reply: ChatReply) -> Iterator[str]:
    for event in chat_service.stream_events(reply):
        yield sse_event(event)


async def sse_llm(
    store: ChatStore,
    graph,
    user_id: int,
    session: ChatSession,
    request: ChatRequest,
) -> AsyncIterator[str]:
    async for event in chat_service.stream_llm(
        store, graph, user_id, session, request
    ):
        yield sse_event(event)


@router.post("", response_model=ChatReply)
async def send_message(
    request: ChatRequest,
    user: CurrentUser,
    registry: Registry,
    store: Store,
) -> ChatReply:
    # Admins talk to the LLM (the chat graph); everyone else gets the
    # sensor-only reply.
    if not user.is_admin:
        return await run_in_threadpool(
            run_chat, store, registry, user.user_id, request
        )

    graph = build_graph()
    ensure_chat_allowed(user.user_id)
    session = open_chat_session(store, user.user_id, request)

    try:
        return await chat_service.complete_llm(
            store, graph, user.user_id, session, request
        )

    except ChatFailedError:
        raise chat_unavailable() from None


@router.post("/stream")
async def stream_message(
    request: ChatRequest,
    user: CurrentUser,
    registry: Registry,
    store: Store,
) -> StreamingResponse:
    if not user.is_admin:
        reply = await run_in_threadpool(
            run_chat, store, registry,
            user.user_id, request
        )

        return StreamingResponse(
            sse_lines(reply),
            media_type=SSE_MEDIA_TYPE, 
            headers=SSE_HEADERS
        )

    graph = build_graph()
    ensure_chat_allowed(user.user_id)
    session = open_chat_session(store, user.user_id, request)

    return StreamingResponse(
        sse_llm(store, graph, 
                user.user_id, 
                session, request),
        media_type=SSE_MEDIA_TYPE,
        headers=SSE_HEADERS,
    )


@router.get("/sessions", response_model=ChatSessionList)
def list_sessions(
    user: CurrentUser,
    store: Store,
    skip: Skip = 0,
    limit: Limit = DEFAULT_PAGE_SIZE,
) -> ChatSessionList:
    items, total = store.list_for_owner(user.user_id, 
                                        skip, limit)

    return ChatSessionList(items=items, 
                           total=total, 
                           skip=skip, 
                           limit=limit)


@router.get("/sessions/{session_id}", response_model=ChatSession)
def get_session(
    session_id: SessionId, user: CurrentUser, store: Store
) -> ChatSession:
    try:
        return store.get(user.user_id, session_id)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc


@router.delete(
    "/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_session(
    session_id: SessionId, 
    user: CurrentUser, 
    store: Store
) -> None:
    try:
        store.delete(user.user_id, session_id)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc
