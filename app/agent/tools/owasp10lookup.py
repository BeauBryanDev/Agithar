from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import tool_error, wrap_result
from app.rag.owasp_top10_2025 import lookup, search_by_cwe

NAME = "owasp10lookup"


class OwaspArgs(BaseModel):
    query: str = Field(
        max_length=40,
        description="A category id like A05 or A05:2025, or a CWE like CWE-89",
    )

    model_config = ConfigDict(extra="forbid")


def find_categories(query: str) -> list[dict]:
    text = query.strip().upper()

    if text.startswith("CWE") or text.isdigit():
        ids = search_by_cwe(text.replace("CWE-", ""))

    else:
        ids = [text]

    entries = [lookup(category_id) for category_id in ids]

    return [entry for entry in entries if entry]


async def run(query: str) -> str:
    try:
        entries = find_categories(query)

    except Exception as exc:
        return tool_error(NAME, exc)

    return wrap_result(NAME, {"found": bool(entries), 
                              "categories": entries}
                       )


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "OWASP Top 10:2025 reference. Give a category id (A01 to A10) or a "
        "CWE id to find the category that lists it."
    ),
    args_schema=OwaspArgs,
)
