from typing import Any

from langchain_core.tools import StructuredTool

from app.agent.tools.common import strict_schema, validation_message
from app.schemas.analysis import AgentVerdict

NAME = "set_verdict"
DESCRIPTION = (
    "Record your final verdict for this case. Call it once, when the "
    "investigation is complete and before set_judgment. Follow the "
    "escalation rule: needs_human must be true exactly when the verdict is "
    "needs_human. Cite only MITRE and OWASP ids you confirmed with a tool."
)


async def run(**fields: Any) -> tuple[str, dict[str, Any]]:
    verdict = AgentVerdict(**fields)

    # The artifact is what the master node reads; the text goes to the model.
    return "verdict recorded", verdict.model_dump()


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=DESCRIPTION,
    args_schema=AgentVerdict,
    response_format="content_and_artifact",
    handle_validation_error=validation_message,
)

WIRE_SCHEMA = strict_schema(NAME, DESCRIPTION, AgentVerdict)
