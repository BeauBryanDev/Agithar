import secrets
from collections.abc import Callable, Iterator
from datetime import datetime, timezone

from app.schemas.analysis import (
    MAX_EVIDENCE_ITEMS,
    AnalyzeRequest,
    AnalyzeResponse,
    DetectorResult,
    EvidenceRef,
)
from app.schemas.chat import (
    MAX_MESSAGES,
    MAX_TITLE_CHARS,
    ChatMessage,
    ChatReply,
    ChatRequest,
    ChatSession,
    ChatStreamEvent,
)
from app.security.sanitize import sanitize_string
from app.services.analysis_service import analyze
from app.services.chat_store import ChatStore
from app.sensors.registry import SensorRegistry

DEFAULT_TITLE = "New session"
NO_ANALYSIS_TEXT = (
    "No sensor could analyze this input. Paste access-log lines, an HTTP "
    "request or a sequence of event ids such as E5 E22 E11."
)
STREAM_CHUNK_CHARS = 80

ReplyFn = Callable[[ChatSession, AnalyzeResponse | None], str]


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_message(
    role: str, content: str, refs: list[EvidenceRef] | None = None
) -> ChatMessage:
    return ChatMessage(
        id=f"msg-{role}-{secrets.token_hex(4)}",
        role=role,
        content=content,
        evidence_refs=refs or [],
        created_at=now_utc(),
    )


def title_from(text: str) -> str:
    first = " ".join(text.split())[:MAX_TITLE_CHARS]

    return sanitize_string(first, MAX_TITLE_CHARS) or DEFAULT_TITLE


def tag_evidence(
    analysis: AnalyzeResponse,
) -> tuple[list[DetectorResult], list[EvidenceRef]]:
    tag = secrets.token_hex(2)
    evidence = [
        item.model_copy(update={"id": f"{tag}-{item.id}"})
        for item in analysis.evidence
    ]
    refs = [
        ref.model_copy(update={"id": f"{tag}-{ref.id}"})
        for ref in analysis.evidence_refs
    ]

    return evidence, refs


def drop_dangling_refs(session: ChatSession) -> None:
    known = {item.id for item in session.evidence}

    for message in session.messages:
        message.evidence_refs = [
            ref for ref in message.evidence_refs if ref.id in known
        ]


def apply_turn(
    session: ChatSession,
    analyst: ChatMessage,
    system: ChatMessage,
    evidence: list[DetectorResult],
) -> None:
    session.messages.extend([analyst, system])
    session.evidence.extend(evidence)
    session.messages = session.messages[-MAX_MESSAGES:]
    session.evidence = session.evidence[-MAX_EVIDENCE_ITEMS:]
    drop_dangling_refs(session)


def default_reply(analysis: AnalyzeResponse | None) -> str:
    if analysis is None:
        return NO_ANALYSIS_TEXT

    return analysis.text


def try_analyze(
    registry: SensorRegistry, text: str
) -> AnalyzeResponse | None:
    try:
        return analyze(registry, AnalyzeRequest(input=text))

    except ValueError:
        return None


def open_session(
    store: ChatStore, owner_id: int, request: ChatRequest
) -> ChatSession:
    if request.session_id is not None:
        return store.get(owner_id, request.session_id)

    return store.create(owner_id, title_from(request.input), now_utc())


def respond(
    store: ChatStore,
    registry: SensorRegistry,
    owner_id: int,
    request: ChatRequest,
    reply_fn: ReplyFn | None = None,
) -> ChatReply:
    session = open_session(store, owner_id, request)
    analysis = try_analyze(registry, request.input)
    evidence: list[DetectorResult] = []
    refs: list[EvidenceRef] = []

    if analysis is not None:
        evidence, refs = tag_evidence(analysis)

    if reply_fn is None:
        text = default_reply(analysis)
    else:
        text = reply_fn(session, analysis)
        refs = []

    analyst = new_message("analyst", request.input)
    system = new_message("system", text, refs)

    def add_turn(stored: ChatSession) -> None:
        apply_turn(stored, analyst, system, evidence)

    store.update(owner_id, session.id, add_turn)

    return ChatReply(
        session_id=session.id, message=system, evidence=evidence
    )


def stream_events(reply: ChatReply) -> Iterator[ChatStreamEvent]:
    content = reply.message.content

    if reply.evidence:
        yield ChatStreamEvent(type="evidence", evidence=reply.evidence)

    for end in range(STREAM_CHUNK_CHARS, len(content), STREAM_CHUNK_CHARS):
        yield ChatStreamEvent(type="token", text=content[:end])

    yield ChatStreamEvent(type="token", text=content)
    yield ChatStreamEvent(type="done", reply=reply)
