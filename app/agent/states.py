
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph.message import add_messages


SECRETARY_STATUS = Literal["pending", "approved", "exhausted"]


class AutomatonState(TypedDict):
    case: dict[str, Any]
    incident_id: int | None
    messages: Annotated[list, add_messages]
    # AgentVerdict.model_dump(): verdict, needs_human, confidence, mitre, owasp, summary
    verdict: dict[str, Any] | None
    findings_blue: dict[str, Any] | None
    findings_red: dict[str, Any] | None
    draft_blue: str | None
    draft_red: str | None
    revision_count_blue: int
    revision_count_red: int
    status_blue: SECRETARY_STATUS
    status_red: SECRETARY_STATUS
    review_feedback_blue: str | None
    review_feedback_red: str | None
    report_md: str | None
    notified: bool


def new_state(
    case: dict[str, Any], incident_id: int | None = None
) -> AutomatonState:
    # Every key is set here, so a node or a router never meets a missing one.
    return {
        "case": case,
        "incident_id": incident_id,
        "messages": [],
        "verdict": None,
        "findings_blue": None,
        "findings_red": None,
        "draft_blue": None,
        "draft_red": None,
        "revision_count_blue": 0,
        "revision_count_red": 0,
        "status_blue": "pending",
        "status_red": "pending",
        "review_feedback_blue": None,
        "review_feedback_red": None,
        "report_md": None,
        "notified": False,
    }


class ChatState(TypedDict):
    operator_id: str  # the admin's user id, as text
    messages: Annotated[list, add_messages]
    tool_turns: int
    # Sensor analysis of a pasted request or log, when the message has one.
    analysis: Any
    reply: str | None


def new_chat_state(
    operator_id: str, messages: list[Any]
) -> ChatState:
    return {
        "operator_id": operator_id,
        "messages": messages,
        "tool_turns": 0,
        "analysis": None,
        "reply": None,
    }
