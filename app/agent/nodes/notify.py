import asyncio
from typing import Any

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.agent.report import force_review
from app.agent.states import AutomatonState
from app.core.logging import get_logger
from app.db.postgresql.repository import mark_notified, save_report
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.schemas.analysis import AgentVerdict
from app.services.notification_service import NotificationError, notify_admin

logger = get_logger("agent.notify")

DB_ERRORS = (SQLAlchemyError, DatabaseNotConfiguredError, ValueError)


def persist(
    incident_id: int,
    verdict: dict[str, Any],
    report_md: str | None,
    notified: bool,
) -> None:
    with get_session_factory()() as session:
        if notified:
            mark_notified(session, incident_id)
        else:
            save_report(session, incident_id, verdict, report_md, False)


async def store(
    incident_id: int | None,
    verdict: dict[str, Any],
    report_md: str | None,
    notified: bool,
) -> None:
    # A database failure must never stop the alert: log the case and go on.
    if incident_id is None:
        logger.error("report not stored: the incident was never saved")
        return

    try:
        await asyncio.to_thread(
            persist, incident_id, verdict, report_md, notified
        )

    except DB_ERRORS as exc:
        logger.error(
            "report not stored for incident %s: %s",
            incident_id, type(exc).__name__,
        )


def read_verdict(raw: dict[str, Any] | None) -> AgentVerdict:
    try:
        return AgentVerdict.model_validate(raw or force_review(None))

    except ValidationError:
        logger.error("verdict in state is invalid, sending it to a human")

        return AgentVerdict.model_validate(force_review(None))


async def notify_admin_node(state: AutomatonState) -> dict[str, Any]:
    verdict = read_verdict(state["verdict"])
    incident_id = state["incident_id"]
    data = verdict.model_dump()

    # A clear false positive is closed quietly: no report, no ping.
    if verdict.verdict == "false_positive":
        await store(incident_id, data, None, False)

        return {"notified": False}

    await store(incident_id, data, state["report_md"], False)

    try:
        await notify_admin(state["case"], verdict, incident_id)

    except NotificationError as exc:
        logger.error("admin alert not sent: %s", exc)

        return {"notified": False}

    if incident_id is not None:
        await store(incident_id, data, None, True)

    return {"notified": True}
