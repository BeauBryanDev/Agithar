import asyncio
from typing import Any, Optional

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.services.coverage_service import overview, technique_coverage

NAME = "detection_coverage"


class CoverageArgs(BaseModel):
    technique: Optional[str] = Field(
        default=None,
        max_length=12,
        description=(
            "An ATT&CK technique id such as T1053.003 for that technique "
            "only. Leave it out for the overall picture and the top gaps"
        ),
    )

    model_config = ConfigDict(extra="forbid")


def find(technique: str | None) -> dict[str, Any]:
    if technique:
        return technique_coverage(technique)

    return overview()


async def run(technique: str | None = None) -> str:
    return await guarded(NAME, asyncio.to_thread(find, technique))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "What can this deployment detect? ATT&CK coverage of the protected "
        "Linux servers in four levels: 3 watched by a live sensor, 2 public "
        "Sigma rules exist for a log that is collected (not deployed), "
        "1 rules exist but need a log that is not collected, 0 blind. "
        "Use it for questions such as what are we blind to, or which "
        "detections could be added with the logs we already have."
    ),
    args_schema=CoverageArgs,
)
