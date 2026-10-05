import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from app.agent.dispatcher import Dispatcher
from app.core.logging import get_logger
from app.db.postgresql.incidents import Incident
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)

logger = get_logger("agent.recovery")

MAX_AGE_HOURS = 2
MAX_CASES = 10


def case_from_incident(incident: Incident) -> dict[str, Any]:
    # The incident row keeps everything the correlator put in the case.
    return {
        "case_id": incident.case_key,
        "ip": incident.ip,
        "severity": incident.severity,
        "composite_score": incident.composite_score,
        "num_sensors": incident.num_sensors,
        "num_strong_sensors": incident.num_strong_sensors,
        "contributing_sensors": incident.contributing_sensors,
        "sensor_scores": incident.sensor_scores,
        "event_counts": incident.event_counts,
        "evidence": incident.evidence,
    }


def load_open_cases() -> list[tuple[dict[str, Any], int]]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=MAX_AGE_HOURS)

    with get_session_factory()() as session:
        rows = session.scalars(
            select(Incident)
            .where(Incident.status == "open", Incident.created_at >= cutoff)
            .order_by(Incident.created_at.desc())
            .limit(MAX_CASES)
        ).all()

        return [(case_from_incident(r), r.incident_id) for r in rows]


async def recover_open_cases(dispatcher: Dispatcher) -> int:
    # After a restart nothing remembers a run that was in progress: the
    # recent incidents still open are run again (the graph has no checkpoint).
    try:
        cases = await asyncio.to_thread(load_open_cases)

    except (SQLAlchemyError, DatabaseNotConfiguredError) as exc:
        logger.error("open incidents not recovered: %s", type(exc).__name__)

        return 0

    return sum(dispatcher.submit(case, incident_id)
               for case, incident_id in reversed(cases))
