import secrets
import time
from datetime import datetime
from functools import cache
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.dynamodb import repository
from app.db.dynamodb.client import (
    TableSchemaError,
    check_table_schema,
    get_dynamodb_table,
)
from app.schemas.analysis import DetectorResult
from app.schemas.chat import (
    MAX_MESSAGES,
    ChatMessage,
    ChatSession,
    ChatSessionSummary,
)
from app.services.chat_history_mapping import (
    ITEM_ERRORS,
    iso,
    message_fields,
    session_from_items,
    summary_from_meta,
)
from app.services.chat_store import (
    ChatHistoryError,
    ChatStore,
    SessionNotFoundError,
)

logger = get_logger("services.chat_history")

SESSION_ID_BYTES = 12
MAX_LISTED = 200
STORE_ERRORS = (BotoCoreError, ClientError)


def error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", "ClientError"))

    return type(exc).__name__


def history_failed(action: str, exc: Exception) -> ChatHistoryError:
    logger.error("chat history %s failed: %s", action, error_code(exc))

    return ChatHistoryError(action)


class DynamoChatStore:
    def __init__(self, table, retention_days: int) -> None:
        self.table = table
        self.retention_seconds = retention_days * 86400

    def expires_at(self) -> int:
        return int(time.time()) + self.retention_seconds

    def owned_meta(self, owner_id: int, session_id: str) -> dict[str, Any]:
        try:
            meta = repository.get_conversation(self.table, session_id)

        except STORE_ERRORS as exc:
            raise history_failed("read", exc) from None

        if meta is None or int(meta.get("user_id", 0)) != owner_id:
            raise SessionNotFoundError(session_id)

        return meta

    def create(
        self,
        owner_id: int,
        title: str,
        created_at: datetime,
        role: str = "operator",
    ) -> ChatSession:
        session = ChatSession(
            id=secrets.token_urlsafe(SESSION_ID_BYTES),
            title=title,
            created_at=created_at,
        )

        try:
            repository.create_conversation(
                self.table, session.id, owner_id, role, session.title,
                iso(created_at), self.expires_at(),
            )

        except STORE_ERRORS as exc:
            raise history_failed("create", exc) from None

        return session

    def get(self, owner_id: int, session_id: str) -> ChatSession:
        meta = self.owned_meta(owner_id, session_id)

        try:
            items = repository.list_messages(
                self.table, session_id, MAX_MESSAGES
            )

        except STORE_ERRORS as exc:
            raise history_failed("read", exc) from None

        return session_from_items(meta, items)

    def append_turn(
        self,
        owner_id: int,
        session_id: str,
        analyst: ChatMessage,
        system: ChatMessage,
        evidence: list[DetectorResult],
    ) -> None:
        messages = [
            message_fields(analyst, []),
            message_fields(system, evidence),
        ]

        try:
            repository.save_turn(
                self.table, session_id, owner_id, messages,
                iso(system.created_at), self.expires_at(),
            )

        except ClientError as exc:
            if error_code(exc) == "TransactionCanceledException":
                raise SessionNotFoundError(session_id) from None

            raise history_failed("save", exc) from None

        except BotoCoreError as exc:
            raise history_failed("save", exc) from None

    def list_for_owner(
        self, owner_id: int, skip: int, limit: int
    ) -> tuple[list[ChatSessionSummary], int]:
        try:
            metas = repository.list_conversations(
                self.table, owner_id, MAX_LISTED
            )

        except STORE_ERRORS as exc:
            raise history_failed("list", exc) from None

        summaries: list[ChatSessionSummary] = []

        for meta in metas[skip:skip + limit]:
            try:
                summaries.append(summary_from_meta(meta))

            except ITEM_ERRORS:
                logger.warning("skipped an unreadable chat conversation")

        return summaries, len(metas)

    def delete(self, owner_id: int, session_id: str) -> None:
        self.owned_meta(owner_id, session_id)

        try:
            repository.delete_conversation(self.table, session_id)

        except STORE_ERRORS as exc:
            raise history_failed("delete", exc) from None


AnyChatStore = ChatStore | DynamoChatStore


@cache
def get_chat_store() -> AnyChatStore:
    # DynamoDB on the box; the in-memory store when it is off or unusable.
    settings = get_settings()

    if not settings.chat_history_dynamodb:
        return ChatStore(settings.session_ttl_seconds)

    try:
        table = get_dynamodb_table()
        check_table_schema(table)

    except TableSchemaError as exc:
        logger.error("chat history table rejected: %s", exc)

        return ChatStore(settings.session_ttl_seconds)

    except STORE_ERRORS as exc:
        logger.error("chat history unavailable: %s", error_code(exc))

        return ChatStore(settings.session_ttl_seconds)

    logger.info("chat history stored in dynamodb")

    return DynamoChatStore(table, settings.chat_history_retention_days)
