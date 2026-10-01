
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph.message import add_messages


class AutomatonState(TypedDict):
    case: dict[str, Any]
    messages: Annotated[list, add_messages]
    verdict: Literal["confirmed", "false_positive", "needs_human"] | None
    report_md: str | None
    notified: bool


class ChatState(TypedDict):
    operator_id: str
    messages: Annotated[list, add_messages]
    retrieved_context: list[dict[str, Any]]
    action_case: dict[str, Any] | None
    