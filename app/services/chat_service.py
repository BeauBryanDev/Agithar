import re
import secrets
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import datetime, timezone

from langchain_core.messages import AIMessage, HumanMessage

from app.agent.states import new_chat_state
from app.core.config import get_settings
from app.core.logging import get_logger
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

logger = get_logger("services.chat")

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


# ---- the admin chat: the LLM graph -------------------------------------

HISTORY_CHARS = 4000
FLUSH_CHARS = 24
RECURSION_LIMIT = 30
UNSAFE_NAME = re.compile(r"[^a-z0-9_]")
FAILED_TEXT = "The chat is unavailable right now. Please try again."
STATUS_LABELS = {
    "shop_traffic": "Reading {shop} traffic",
    "shop_recent_errors": "Reading {shop} errors",
    "shop_incidents": "Checking {shop} incidents",
    "server_status": "Checking the server",
    "ingestion_status": "Checking the log feed",
    "incident_history": "Looking up earlier incidents",
    "recent_incidents": "Looking up recent incidents",
    "threat_intelligence": "Checking IP reputation",
    "cve_lookup": "Looking up a CVE",
}


class ChatFailedError(Exception):
    pass


def history_messages(session: ChatSession, limit: int) -> list:
    # The last turns of the session as model messages (system = Agithar).
    kept = session.messages[-limit:] if limit > 0 else []
    out: list = []

    for message in kept:
        text = sanitize_string(message.content, HISTORY_CHARS,
                               keep_newlines=True)
        out.append(
            HumanMessage(text) if message.role == "analyst"
            else AIMessage(text)
        )

    return out


def chunk_text(chunk: object) -> str:
    # Only the answer text of a streamed chunk, never thinking or tool input.
    content = getattr(chunk, "content", "")

    if isinstance(content, str):
        return content

    return "".join(
        block.get("text", "")
        for block in content
        if isinstance(block, dict) and block.get("type") == "text"
    )


def status_text(call: dict) -> str:
    name = UNSAFE_NAME.sub("", str(call.get("name", "")).lower())[:40]
    shop = UNSAFE_NAME.sub("", str(call.get("args", {}).get("shop", "")))
    label = STATUS_LABELS.get(name)

    if label is None:
        return f"Using {name or 'a tool'}"

    return label.format(shop=shop[:32] or "shop")


async def stream_llm(
    store: ChatStore,
    graph: object,
    owner_id: int,
    session: ChatSession,
    request: ChatRequest,
    is_admin: bool = False,
) -> AsyncIterator[ChatStreamEvent]:
    # Runs the chat graph and yields status, evidence and cumulative token
    # events, then saves the turn and yields done. A failure yields one
    # error event and saves nothing.
    settings = get_settings()
    messages = [
        *history_messages(session, settings.chat_history_messages),
        HumanMessage(request.input),
    ]
    state = new_chat_state(str(owner_id), messages, is_admin)
    evidence: list[DetectorResult] = []
    text, sent, reply_text = "", 0, None

    try:
        async for mode, data in graph.astream(  # type: ignore[attr-defined]
            state,
            config={"recursion_limit": RECURSION_LIMIT},
            stream_mode=["messages", "updates"],
        ):
            if mode == "messages":
                chunk, meta = data

                if meta.get("langgraph_node") == "agent":
                    text += chunk_text(chunk)

                    if len(text) - sent >= FLUSH_CHARS:
                        sent = len(text)
                        yield ChatStreamEvent(type="token", text=text)

                continue

            for node, update in data.items():
                update = update or {}

                if node == "triage" and update.get("analysis") is not None:
                    evidence, _ = tag_evidence(update["analysis"])
                    yield ChatStreamEvent(type="evidence", evidence=evidence)

                elif node == "agent":
                    calls = getattr(update["messages"][-1], "tool_calls", [])

                    for call in calls:
                        yield ChatStreamEvent(
                            type="status", text=status_text(call)
                        )

                    if calls:
                        text, sent = "", 0

                elif node == "finish":
                    reply_text = update["reply"]

    except Exception as exc:
        logger.error("chat graph failed: %s", type(exc).__name__)
        yield ChatStreamEvent(type="error", text=FAILED_TEXT)

        return

    if reply_text is None:
        yield ChatStreamEvent(type="error", text=FAILED_TEXT)

        return

    analyst = new_message("analyst", request.input)
    system = new_message("system", reply_text)

    def add_turn(stored: ChatSession) -> None:
        apply_turn(stored, analyst, system, evidence)

    store.update(owner_id, session.id, add_turn)
    reply = ChatReply(session_id=session.id, message=system,
                      evidence=evidence)

    yield ChatStreamEvent(type="token", text=reply_text)
    yield ChatStreamEvent(type="done", reply=reply)


async def complete_llm(
    store: ChatStore,
    graph: object,
    owner_id: int,
    session: ChatSession,
    request: ChatRequest,
    is_admin: bool = False,
) -> ChatReply:
    async for event in stream_llm(
        store, graph, owner_id, session, request, is_admin
    ):
        if event.type == "done" and event.reply is not None:
            return event.reply

        if event.type == "error":
            break

    raise ChatFailedError()
