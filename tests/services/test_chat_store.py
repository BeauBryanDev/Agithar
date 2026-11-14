from datetime import datetime, timezone

import pytest

from app.schemas.analysis import DetectorResult, EvidenceRef
from app.schemas.chat import MAX_MESSAGES, ChatMessage
from app.services import chat_store as svc


NOW = datetime(2026, 11, 14, 10, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    fake = Clock()
    monkeypatch.setattr(svc.time, "monotonic", fake)

    return fake


def message(role: str, content: str, refs=None) -> ChatMessage:
    return ChatMessage(
        id=f"msg-{role}-0001",
        role=role,
        content=content,
        evidence_refs=refs or [],
        created_at=NOW,
    )


def evidence(item_id: str) -> DetectorResult:
    return DetectorResult(
        id=item_id,
        detector="http_payload_sensor",
        anomaly_score=0.9,
        verdict="anomaly",
        threshold=0.25,
    )


def test_create_and_get_returns_copies(clock):
    store = svc.ChatStore(ttl_seconds=60)
    session = store.create(1, "First", NOW)
    session.title = "tampered"

    assert store.get(1, session.id).title == "First"


def test_other_owner_sees_not_found(clock):
    store = svc.ChatStore(ttl_seconds=60)
    session = store.create(1, "Mine", NOW)

    with pytest.raises(svc.SessionNotFoundError):
        store.get(2, session.id)

    with pytest.raises(svc.SessionNotFoundError):
        store.delete(2, session.id)

    assert store.get(1, session.id).id == session.id


def test_sessions_expire_after_ttl(clock):
    store = svc.ChatStore(ttl_seconds=60)
    session = store.create(1, "Old", NOW)
    clock.value += 61

    with pytest.raises(svc.SessionNotFoundError):
        store.get(1, session.id)


def test_per_owner_limit(clock, monkeypatch):
    monkeypatch.setattr(svc, "MAX_SESSIONS_PER_OWNER", 2)
    store = svc.ChatStore(ttl_seconds=60)
    store.create(1, "a", NOW)
    store.create(1, "b", NOW)

    with pytest.raises(svc.SessionLimitError):
        store.create(1, "c", NOW)

    assert store.create(2, "other user", NOW)


def test_message_cap_keeps_newest(clock):
    store = svc.ChatStore(ttl_seconds=60)
    session = store.create(1, "Long", NOW)

    for index in range(MAX_MESSAGES):
        store.append_turn(
            1, session.id,
            message("analyst", f"q{index}"),
            message("system", f"a{index}"),
            [],
        )

    stored = store.get(1, session.id)

    assert len(stored.messages) == MAX_MESSAGES
    assert stored.messages[-1].content == f"a{MAX_MESSAGES - 1}"


def test_dangling_evidence_refs_are_dropped(clock):
    store = svc.ChatStore(ttl_seconds=60)
    session = store.create(1, "Refs", NOW)
    refs = [
        EvidenceRef(id="known", claim_span=(0, 4)),
        EvidenceRef(id="ghost", claim_span=(0, 4)),
    ]
    store.append_turn(
        1, session.id,
        message("analyst", "test"),
        message("system", "seen it", refs),
        [evidence("known")],
    )
    stored = store.get(1, session.id)

    assert [ref.id for ref in stored.messages[-1].evidence_refs] == ["known"]
