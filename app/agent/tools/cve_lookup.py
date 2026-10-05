from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import tool_error, wrap_result
from app.services.cve_service import lookup_cve

NAME = "cve_lookup"


class CveArgs(BaseModel):
    cve_id: str = Field(max_length=32, 
                        description="For example CVE-2019-8134")

    model_config = ConfigDict(extra="forbid")


async def run(cve_id: str) -> str:
    try:
        result = await lookup_cve(cve_id)

    except Exception as exc:
        return tool_error(NAME, exc)

    return wrap_result(NAME, 
                       result.model_dump(mode="json", 
                                         exclude_none=True)
                       )


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Look up one CVE: summary, CVSS, CWE, OWASP category, references and "
        "known public exploit METADATA (never exploit code). The result says "
        "its source and, when nothing is found, how fresh the dataset is."
    ),
    args_schema=CveArgs,
)
