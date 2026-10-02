import secrets
import threading
import time
from datetime import datetime
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache

from app.core.config import get_settings
from app.schemas.chat import ChatSession, ChatSessionSummary

MAX_SESSIONS = 1000
MAX_SESSIONS_PER_OWNER = 50
SESSION_ID_BYTES = 12


def created_key(session: ChatSession):
    return session.created_at


class SessionNotFoundError(Exception):
    pass


class SessionLimitError(Exception):
    pass


@dataclass
class StoredSession:
    owner_id: int
    session: ChatSession
    last_seen: float


class ChatStore:
    def __init__(self, ttl_seconds: int) -> None:
        self.ttl_seconds = ttl_seconds
        self.items: dict[str, StoredSession] = {}
        self.lock = threading.Lock()

    def evict_expired(self, now: float) -> None:
        cutoff = now - self.ttl_seconds
        expired = [
            key for key, item in self.items.items()
            if item.last_seen < cutoff
        ]

        for key in expired:
            del self.items[key]

    def find(self, owner_id: int, session_id: str) -> StoredSession:
        self.evict_expired(time.monotonic())
        item = self.items.get(session_id)

        if item is None or item.owner_id != owner_id:
            raise SessionNotFoundError(session_id)

        return item

    def create(
        self, owner_id: int, title: str, created_at: datetime
    ) -> ChatSession:
        with self.lock:
            self.evict_expired(time.monotonic())
            owned = [i for i in self.items.values() if i.owner_id == owner_id]

            if len(self.items) >= MAX_SESSIONS:
                raise SessionLimitError("too many sessions")

            if len(owned) >= MAX_SESSIONS_PER_OWNER:
                raise SessionLimitError("too many sessions for this user")

            session = ChatSession(
                id=secrets.token_urlsafe(SESSION_ID_BYTES),
                title=title,
                created_at=created_at,
            )
            self.items[session.id] = StoredSession(
                owner_id, session, time.monotonic()
            )

            return session.model_copy(deep=True)

    def get(self, owner_id: int, session_id: str) -> ChatSession:
        with self.lock:
            item = self.find(owner_id, session_id)

            return item.session.model_copy(deep=True)

    def update(
        self,
        owner_id: int,
        session_id: str,
        mutate: Callable[[ChatSession], None],
    ) -> ChatSession:
        with self.lock:
            item = self.find(owner_id, session_id)
            mutate(item.session)
            item.last_seen = time.monotonic()

            return item.session.model_copy(deep=True)

    def list_for_owner(
        self, owner_id: int, skip: int, limit: int
    ) -> tuple[list[ChatSessionSummary], int]:
        with self.lock:
            self.evict_expired(time.monotonic())
            owned = [
                i.session for i in self.items.values()
                if i.owner_id == owner_id
            ]

        owned.sort(key=created_key, reverse=True)
        page = owned[skip:skip + limit]
        summaries = [
            ChatSessionSummary(
                id=s.id, title=s.title, created_at=s.created_at
            )
            for s in page
        ]

        return summaries, len(owned)

    def delete(self, owner_id: int, session_id: str) -> None:
        with self.lock:
            self.find(owner_id, session_id)
            del self.items[session_id]


@cache
def get_chat_store() -> ChatStore:
    return ChatStore(get_settings().session_ttl_seconds)
