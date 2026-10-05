import asyncio
from typing import Any

from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError

from app.agent.findings_builder import build_blue_findings, build_red_findings
from app.agent.investigate import Run, fallback_verdict, investigate
from app.agent.report import build_report, force_review
from app.agent.review import MAX_REVISIONS, check_draft
from app.agent.states import AutomatonState
from app.core.logging import get_logger
from app.db.postgresql.repository import save_incident
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.schemas.analysis import AgentVerdict

logger = get_logger("agent.master")

COLORS = ("blue", "red")

# Used only when the model never called set_judgment (a quiet, cautious set).
DEFAULT_JUDGMENT = {
    "blue_actions": ["monitor_ip", "review_logs"],
    "red_impact": ["unknown"],
    "red_components": [],
    "red_actions": ["enable_monitoring"],
}


def review_color(state: AutomatonState, color: str) -> dict[str, Any]:
    if state[f"status_{color}"] != "pending":
        return {}

    problems = check_draft(state[f"draft_{color}"], color)

    if not problems:
        return {
            f"status_{color}": "approved",
            f"review_feedback_{color}": None,
        }

    count = state[f"revision_count_{color}"]

    # Sent back twice already: stop here, the master finishes this draft.
    if count >= MAX_REVISIONS:
        return {
            f"status_{color}": "exhausted",
            f"review_feedback_{color}": None,
        }

    return {
        f"revision_count_{color}": count + 1,
        f"review_feedback_{color}": "; ".join(problems),
    }


def master_review_node(state: AutomatonState) -> dict[str, Any]:
    # Deterministic checks only. An LLM pass can be added after them later.
    update: dict[str, Any] = {}

    for color in COLORS:
        update.update(review_color(state, color))

    return update


def compose_final_report_node(state: AutomatonState) -> dict[str, Any]:
    verdict = state["verdict"]
    unapproved = any(
        state[f"status_{color}"] != "approved" for color in COLORS
    )

    if unapproved or verdict is None:
        verdict = force_review(verdict)

    report = build_report(
        state["case"],
        state["incident_id"],
        verdict,
        (state["draft_blue"], state["status_blue"]),
        (state["draft_red"], state["status_red"]),
    )

    return {"verdict": verdict, "report_md": report}


def store_incident(case: dict[str, Any]) -> int:
    with get_session_factory()() as session:
        return save_incident(session, case).incident_id


async def ensure_incident(
    case: dict[str, Any], incident_id: int | None
) -> int | None:
    # event_service saves the incident when the case escalates. If the
    # database was down then, save it now (save_incident is save-or-update).
    if incident_id is not None:
        return incident_id

    try:
        return await asyncio.to_thread(store_incident, case)

    except (SQLAlchemyError, DatabaseNotConfiguredError) as exc:
        logger.error("incident still not saved: %s", type(exc).__name__)

        return None


def build_findings(
    case: dict[str, Any],
    verdict: AgentVerdict,
    run: Run,
    incident_saved: bool,
) -> dict[str, Any]:
    judgment = run.judgment or DEFAULT_JUDGMENT

    try:
        return make_findings(case, verdict, run, judgment, incident_saved)

    except ValidationError:
        logger.error("judgment rejected, using the default judgment")

        return make_findings(
            case, verdict, run, DEFAULT_JUDGMENT, incident_saved
        )


def make_findings(
    case: dict[str, Any],
    verdict: AgentVerdict,
    run: Run,
    judgment: dict[str, Any],
    incident_saved: bool,
) -> dict[str, Any]:
    blue = build_blue_findings(
        case, verdict, run.records, judgment["blue_actions"], incident_saved
    )
    red = build_red_findings(
        case,
        verdict,
        run.records,
        judgment["red_impact"],
        judgment["red_components"],
        judgment["red_actions"],
        incident_saved,
    )

    return {"findings_blue": blue, "findings_red": red}


async def master_investigate_node(state: AutomatonState) -> dict[str, Any]:
    case = state["case"]
    incident_id = await ensure_incident(case, state["incident_id"])
    run = Run()

    # A failure here must not kill the run: the case goes to a human.
    try:
        run = await investigate(case)

    except Exception as exc:
        logger.error("investigation failed: %s", type(exc).__name__)

    verdict = run.verdict or fallback_verdict()
    update: dict[str, Any] = {
        "incident_id": incident_id,
        "verdict": verdict.model_dump(),
    }

    # A false positive has no findings: it skips the secretaries.
    if verdict.verdict != "false_positive":
        saved = incident_id is not None
        update.update(build_findings(case, verdict, run, saved))

    return update
