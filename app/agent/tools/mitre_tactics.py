from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.rag.mitre_attack import attribution, list_tactics, search_by_tactic

NAME = "mitre_tactics"
MAX_TECHNIQUES = 25


class TacticArgs(BaseModel):
    tactic: str | None = Field(
        default=None,
        max_length=40,
        description="A tactic shortname like reconnaissance; omit to list all",
    )

    model_config = ConfigDict(extra="forbid")


async def find(tactic: str | None) -> dict:
    if not tactic:
        data = {"tactics": list_tactics()}

    else:
        data = search_by_tactic(tactic.strip().lower(), MAX_TECHNIQUES)

    return {**data, "attribution": attribution()}


async def run(tactic: str | None = None) -> str:
    return await guarded(NAME, find(tactic))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "MITRE ATT&CK tactics. With no argument it lists every tactic; with "
        "a tactic shortname it lists up to 25 of its techniques. Note ATT&CK "
        "v19 has stealth and defense-impairment, not defense-evasion."
    ),
    args_schema=TacticArgs,
)
