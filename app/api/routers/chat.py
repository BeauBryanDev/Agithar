from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import StreamingResponse

from app.api.deps import CurrentUser, Registry
from app.schemas.chat import (
    ChatReply,
    ChatRequest,
    ChatSession,
    ChatSessionList,
)
from app.services import chat_service
from app.services.chat_store import (
    ChatStore,
    SessionLimitError,
    SessionNotFoundError,
    get_chat_store,
)

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
SSE_MEDIA_TYPE = "text/event-stream"

router = APIRouter(prefix="/chat", tags=["chat"])

Store = Annotated[ChatStore, Depends(get_chat_store)]
Skip = Annotated[int, Query(ge=0)]
Limit = Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)]
SessionId = Annotated[
    str, Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
]


def session_not_found() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
    )


def session_limit() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many chat sessions",
    )


def run_chat(
    store: ChatStore,
    registry: Registry,
    user_id: int,
    request: ChatRequest,
) -> ChatReply:
    try:
        return chat_service.respond(store, registry, user_id, request)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc

    except SessionLimitError as exc:
        raise session_limit() from exc


def sse_lines(reply: ChatReply) -> Iterator[str]:
    for event in chat_service.stream_events(reply):
        yield f"data: {event.model_dump_json(exclude_none=True)}\n\n"


@router.post("", response_model=ChatReply)
def send_message(
    request: ChatRequest,
    user: CurrentUser,
    registry: Registry,
    store: Store,
) -> ChatReply:
    return run_chat(store, registry, user.user_id, request)


@router.post("/stream")
def stream_message(
    request: ChatRequest,
    user: CurrentUser,
    registry: Registry,
    store: Store,
) -> StreamingResponse:
    reply = run_chat(store, registry, user.user_id, request)

    return StreamingResponse(sse_lines(reply), media_type=SSE_MEDIA_TYPE)


@router.get("/sessions", response_model=ChatSessionList)
def list_sessions(
    user: CurrentUser,
    store: Store,
    skip: Skip = 0,
    limit: Limit = DEFAULT_PAGE_SIZE,
) -> ChatSessionList:
    items, total = store.list_for_owner(user.user_id, skip, limit)

    return ChatSessionList(items=items, total=total, skip=skip, limit=limit)


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
    session_id: SessionId, user: CurrentUser, store: Store
) -> None:
    try:
        store.delete(user.user_id, session_id)

    except SessionNotFoundError as exc:
        raise session_not_found() from exc
