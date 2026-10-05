from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import tool_error, wrap_result
from app.rag.mitre_attack import (
    attribution,
    check_technique,
    lookup,
    normalize_id,
    search_by_name,
)

NAME = "mitre_lookup"
MAX_NAME_RESULTS = 5


class MitreArgs(BaseModel):
    query: str = Field(
        max_length=100,
        description="A technique id such as T1595.002, or words from its name",
    )

    model_config = ConfigDict(extra="forbid")


def find(query: str) -> dict:
    technique_id = normalize_id(query)

    if technique_id is None:
        return {"matches": search_by_name(query, MAX_NAME_RESULTS)}

    entry = lookup(technique_id)

    # A revoked or unknown id has no entry: the check says which one it is.
    return {"technique": entry} if entry else check_technique(technique_id)


async def run(query: str) -> str:
    try:
        data = find(query)
        data["attribution"] = attribution()

    except Exception as exc:
        return tool_error(NAME, exc)

    return wrap_result(NAME, data)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "MITRE ATT&CK Enterprise lookup. Give a technique id to get its "
        "tactics, description, mitigations and detections; a revoked id "
        "returns its replacement; or give words to search technique names. "
        "Only cite technique ids this tool confirms."
    ),
    args_schema=MitreArgs,
)
