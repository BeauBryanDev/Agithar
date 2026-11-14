from datetime import datetime, timezone

from app.schemas.analysis import DetectorResult, EvidenceRef
from app.schemas.chat import ChatMessage
from app.services import chat_history_mapping as svc


NOW = datetime(2026, 11, 14, 10, 0, 0, 123456, tzinfo=timezone.utc)
META = {
    "conversation_id": "conv-1",
    "title": "SQLi question",
    "started_at": svc.iso(NOW),
}


def stored_turn() -> list[dict]:
    item = DetectorResult(
        id="e1", detector="http_payload_sensor", anomaly_score=0.97,
        verdict="anomaly", threshold=0.25,
    )
    message = ChatMessage(
        id="msg-system-ab12",
        role="system",
        content="Payload looks like SQL injection.",
        evidence_refs=[EvidenceRef(id="e1", claim_span=(0, 7))],
        created_at=NOW,
    )

    return [svc.message_fields(message, [item])]


def test_round_trip_message_and_evidence():
    session = svc.session_from_items(META, stored_turn())

    assert session.id == "conv-1"
    assert session.created_at == NOW
    assert session.messages[0].evidence_refs[0].id == "e1"
    assert session.evidence[0].anomaly_score == 0.97


def test_corrupt_row_is_skipped():
    items = stored_turn()
    items.append({"message_id": "msg-x", "role": "system",
                  "content": "x", "created_at": svc.iso(NOW),
                  "evidence_json": "{not json"})
    items.append({"role": "hacker", "content": "no id"})
    session = svc.session_from_items(META, items)

    assert len(session.messages) == 1


def test_summary_from_meta():
    summary = svc.summary_from_meta(META)

    assert summary.id == "conv-1"
    assert summary.title == "SQLi question"
    assert summary.created_at == NOW
