import json
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from app.core.logging import get_logger
from app.schemas.analysis import MAX_EVIDENCE_ITEMS, DetectorResult
from app.schemas.chat import (
    MAX_MESSAGES,
    ChatMessage,
    ChatSession,
    ChatSessionSummary,
)
from app.services.chat_store import drop_dangling_refs

logger = get_logger("services.chat_history")

MAX_EVIDENCE_JSON = 200_000
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
ITEM_ERRORS = (KeyError, ValueError, ValidationError)


def iso(moment: datetime) -> str:
    # Fixed width so the sort keys order by time.
    return moment.astimezone(timezone.utc).strftime(TIME_FORMAT)


def parse_time(value: str) -> datetime:
    return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)


def message_fields(
    message: ChatMessage, evidence: list[DetectorResult]
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "message_id": message.id,
        "role": message.role,
        "content": message.content,
        "created_at": iso(message.created_at),
    }

    if message.evidence_refs:
        refs = [ref.model_dump(mode="json") for ref in message.evidence_refs]
        fields["refs_json"] = json.dumps(refs)

    if evidence:
        dumped = [item.model_dump(mode="json") for item in evidence]
        text = json.dumps(dumped)

        if len(text) <= MAX_EVIDENCE_JSON:
            fields["evidence_json"] = text
        else:
            logger.warning("chat evidence too large to store, dropped")

    return fields


def message_from_item(item: dict[str, Any]) -> ChatMessage:
    refs = json.loads(item.get("refs_json", "[]"))

    return ChatMessage(
        id=item["message_id"],
        role=item["role"],
        content=item["content"],
        evidence_refs=refs,
        created_at=parse_time(item["created_at"]),
    )


def evidence_from_item(item: dict[str, Any]) -> list[DetectorResult]:
    raw = json.loads(item.get("evidence_json", "[]"))

    return [DetectorResult.model_validate(entry) for entry in raw]


def session_from_items(
    meta: dict[str, Any], items: list[dict[str, Any]]
) -> ChatSession:
    # Stored rows are validated again; a corrupt row is skipped.
    messages: list[ChatMessage] = []
    evidence: list[DetectorResult] = []

    for item in items:
        try:
            message = message_from_item(item)
            item_evidence = evidence_from_item(item)

        except ITEM_ERRORS:
            logger.warning("skipped an unreadable chat message")
            continue

        messages.append(message)
        evidence.extend(item_evidence)

    session = ChatSession.model_construct(
        id=meta["conversation_id"],
        title=meta.get("title", ""),
        created_at=parse_time(meta["started_at"]),
        messages=messages[-MAX_MESSAGES:],
        evidence=evidence[-MAX_EVIDENCE_ITEMS:],
    )
    drop_dangling_refs(session)

    return ChatSession.model_validate(session.model_dump())


def summary_from_meta(meta: dict[str, Any]) -> ChatSessionSummary:
    return ChatSessionSummary(
        id=meta["conversation_id"],
        title=meta.get("title", ""),
        created_at=parse_time(meta["started_at"]),
    )
