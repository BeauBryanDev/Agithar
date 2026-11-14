import hashlib
import time

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.correlator.correlator import Correlator
from app.db.postgresql.incidents import Incident
from app.schemas.events import SensorEventIn
from app.sensors.base import SensorResult
from app.services import event_service as svc


IP = "198.51.100.23"
NOW = 1_790_000_000.0


def result(sensor: str, score: float, anomalous: bool = True):
    return SensorResult(sensor=sensor, score=score, is_anomalous=anomalous)


def push(correlator, session, sensor, score, anomalous=True, **context):
    return svc.ingest_result(
        correlator,
        session,
        result(sensor, score, anomalous),
        IP,
        NOW,
        **context,
    )


def count_incidents(session: Session) -> int:
    return session.scalar(select(func.count()).select_from(Incident))


def test_non_anomalous_event_does_not_escalate(db_session: Session):
    outcome = push(Correlator(), db_session, "http_payload_sensor", 0.1, False)

    assert outcome.escalated is False
    assert count_incidents(db_session) == 0


def test_single_strong_hit_is_saved_as_medium(db_session: Session):
    outcome = push(Correlator(), db_session, "http_payload_sensor", 0.97)

    assert outcome.escalated and outcome.saved
    assert outcome.case["severity"] == "medium"
    assert outcome.incident_id is not None


def test_rising_severity_updates_the_same_incident(db_session: Session):
    correlator = Correlator()
    first = push(correlator, db_session, "http_payload_sensor", 0.97)
    second = push(correlator, db_session, "recon_sensor", 0.99)
    third = push(correlator, db_session, "recon_sensor", 0.99)

    assert second.case["severity"] == "high"
    assert second.incident_id == first.incident_id
    assert third.escalated is False
    assert count_incidents(db_session) == 1


def test_bad_event_rejected_without_echo(db_session: Session):
    with pytest.raises(svc.EventRejectedError) as info:
        svc.ingest_result(
            Correlator(),
            db_session,
            result("http_payload_sensor", 0.9),
            "not-an-ip<script>",
            NOW,
        )

    assert str(info.value) == "event rejected"


@pytest.mark.parametrize("broken", ["no_session", "db_down"])
def test_database_failure_never_drops_the_case(
    db_session: Session, monkeypatch: pytest.MonkeyPatch, broken: str
):
    def failing_save(session, case):
        raise OperationalError("insert", {}, Exception("down"))

    monkeypatch.setattr(svc, "save_incident", failing_save)
    session = None if broken == "no_session" else db_session
    outcome = push(Correlator(), session, "http_payload_sensor", 0.97)

    assert outcome.escalated is True
    assert outcome.saved is False
    assert outcome.case is not None


def test_context_strips_query_and_hashes_user_agent(db_session: Session):
    outcome = push(
        Correlator(),
        db_session,
        "http_payload_sensor",
        0.97,
        method="get",
        target="/search?q=secret-token",
        user_agent="sqlmap/1.8",
        status=200,
    )
    context = outcome.case["evidence"][0]["context"]

    assert context["path"] == "/search"
    assert context["method"] == "GET"
    assert context["user_agent_sha256"] == hashlib.sha256(
        b"sqlmap/1.8"
    ).hexdigest()
    assert "sqlmap" not in str(outcome.case)


def test_ingest_event_from_schema(db_session: Session):
    event = SensorEventIn(
        source_sensor="http_payload_sensor",
        score=0.98,
        is_anomalous=True,
        ip=IP,
        timestamp=NOW,
    )
    outcome = svc.ingest_event(Correlator(), db_session, event)

    assert outcome.saved is True
    assert outcome.case["ip"] == IP


def test_timestamp_plausibility_window():
    now = time.time()

    assert svc.timestamp_is_plausible(now, now)
    assert svc.timestamp_is_plausible(now + 100, now)
    assert not svc.timestamp_is_plausible(now + 500, now)
    assert not svc.timestamp_is_plausible(now - 1000, now)
