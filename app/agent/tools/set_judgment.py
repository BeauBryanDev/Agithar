from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import strict_schema, validation_message
from app.schemas.findings import (
    BLUE_ACTION,
    COMPONENT,
    IMPACT,
    RED_ACTION,
)

NAME = "set_judgment"
DESCRIPTION = (
    "Record your judgment for the two secretaries, after set_verdict. Call it "
    "once. Use only the allowed values; code builds every other field of "
    "their findings. Use no_action when no blue action is needed."
)


class JudgmentArgs(BaseModel):
    # The allowed values come from the Literal lists in schemas/findings.py,
    # so they are not repeated in the prompt.
    blue_actions: list[BLUE_ACTION] = Field(min_length=1, max_length=9)
    red_impact: list[IMPACT] = Field(max_length=5)
    red_components: list[COMPONENT] = Field(max_length=6)
    red_actions: list[RED_ACTION] = Field(max_length=8)

    model_config = ConfigDict(extra="forbid")


async def run(**fields: Any) -> tuple[str, dict[str, Any]]:
    judgment = JudgmentArgs(**fields)

    return "judgment recorded", judgment.model_dump()


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=DESCRIPTION,
    args_schema=JudgmentArgs,
    response_format="content_and_artifact",
    handle_validation_error=validation_message,
)

WIRE_SCHEMA = strict_schema(NAME, DESCRIPTION, JudgmentArgs)
