from functools import lru_cache
from pathlib import Path
from typing import Any

from app.agent.llm.secretaries_client import generate_secretary_report
from app.agent.review import MAX_DRAFT_CHARS
from app.agent.states import AutomatonState
from app.core.logging import get_logger
from app.security.sanitize import escape_json, sanitize_string

logger = get_logger("agent.secretary")

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"
MAX_FEEDBACK_CHARS = 600
# Room above the review limit, 
# so an over-long draft is still detected.
DRAFT_SLACK_CHARS = 500


@lru_cache(maxsize=2)
def load_prompt(color: str) -> str:
    # Each secretary reads only its own rules.
    return (PROMPT_DIR / f"{color}_secretary.md").read_text(encoding="utf-8")


def build_message(findings: dict[str, Any], feedback: str | None) -> str:
    # The findings are sanitized structured data, escaped so that nothing in
    # them can close the tag. The feedback comes from our own review code.
    parts = ["<findings>", escape_json(findings), "</findings>"]

    if feedback:
        clean = sanitize_string(feedback, MAX_FEEDBACK_CHARS)
        parts += ["<review_feedback>", clean, "</review_feedback>"]

    return "\n".join(parts)


async def write_draft(state: AutomatonState, 
                      color: str
                      ) -> dict[str, Any]:
    # The secretary reads the findings and review feedback, and returns a draft report.
    findings = state[f"findings_{color}"]
    key = f"draft_{color}"

    if findings is None:
        logger.error("%s secretary has no findings", color)

        return {key: None}

    message = build_message(findings, state[f"review_feedback_{color}"])

    # A model failure must not kill the run: an empty draft is sent back by
    # the review step and, after two tries, reported as unapproved.
    try:
        text = await generate_secretary_report(load_prompt(color), message)

    except Exception as exc:
        logger.error("%s secretary failed: %s", color, type(exc).__name__)
        text = ""

    draft = sanitize_string(
        text, MAX_DRAFT_CHARS + DRAFT_SLACK_CHARS, keep_newlines=True
    )

    return {key: draft or None}
