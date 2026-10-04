from dataclasses import dataclass
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.correlator.correlator import Correlator, event_from_result
from app.db.postgresql.repository import save_incident
from app.db.postgresql.session import DatabaseNotConfiguredError
from app.schemas.events import EventContext, SensorEventIn
from app.sensors.base import SensorResult


logger = get_logger("services.event")


class EventRejectedError(Exception):
    pass


@dataclass(frozen=True)
class EventOutcome:
    escalated: bool
    case: dict[str, Any] | None = None
    incident_id: int | None = None
    saved: bool = False


def build_context(
    method: str | None,
    target: str | None,
    user_agent: str | None,
    status: int | None,
) -> EventContext | None:
    fields = (method, target, user_agent, status)

    # all is None: no context to build, return None
    if all(field is None for field in fields):
        return None

    return EventContext.from_raw(method, 
                                 target, 
                                 user_agent, 
                                 status)


def persist_case(
    session: Session | None, 
    case: dict[str, Any]
) -> EventOutcome:
    # An escalation is never dropped because the database failed: the case
    # still goes back to the caller and the failure is logged.
    if session is None:
        logger.error(
            "incident not saved: no database session",
            extra={"case_id": case["case_id"]},
        )

        return EventOutcome(escalated=True, case=case)

    try:
        incident = save_incident(session, case)
        
    except (SQLAlchemyError, DatabaseNotConfiguredError) as exc:
        session.rollback()
        logger.error(
            "incident not saved: %s",
            type(exc).__name__,
            extra={"case_id": case["case_id"]},
        )

        return EventOutcome(escalated=True, case=case)

    logger.info(
        "incident saved",
        extra={
            "case_id": case["case_id"],
            "incident_id": incident.incident_id,
        },
    )

    return EventOutcome(
        escalated=True,
        case=case,
        incident_id=incident.incident_id,
        saved=True,
    )


def process_event(
    correlator: Correlator,
    session: Session | None,
    event: dict[str, Any],
) -> EventOutcome:
    try:
        case = correlator.ingest(event)
    except ValueError:
        # The correlator already logged the reason; the caller gets no
        # echo of the rejected input.
        raise EventRejectedError("event rejected") from None

    if case is None:
        return EventOutcome(escalated=False)

    return persist_case(session, case)


def ingest_event(
    correlator: Correlator,
    session: Session | None,
    event: SensorEventIn,
) -> EventOutcome:
    return process_event(
        correlator, session,
        event.model_dump(exclude_none=True)
    )


def ingest_result(
    correlator: Correlator,
    session: Session | None,
    result: SensorResult,
    ip: str,
    timestamp: float,
    *,
    method: str | None = None,
    target: str | None = None,
    user_agent: str | None = None,
    status: int | None = None,
) -> EventOutcome:
    
    event = event_from_result(result, 
                              ip, timestamp)

    try:
        context = build_context(method, 
                                target, 
                                user_agent, 
                                status
                                )
        
    except ValueError:
        raise EventRejectedError("event rejected") from None

    if context is not None:
        event["context"] = context.model_dump(exclude_none=True)

    return process_event(correlator, 
                         session, 
                         event)
