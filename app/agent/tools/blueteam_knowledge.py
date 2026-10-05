import asyncio

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import tool_error, wrap_result
from app.rag.retriever import format_hits, search

NAME = "blueteam_knowledge"
TOP_K = 3


class KnowledgeArgs(BaseModel):
    question: str = Field(
        max_length=500,
        description="A question phrased like a textbook topic",
    )

    model_config = ConfigDict(extra="forbid")


async def search_namespace(tool: str, 
                           namespace: str, 
                           question: str
                           ) -> str:
    try:
        hits = await asyncio.to_thread(search,
                                       question, 
                                       namespace, 
                                       TOP_K)

    except Exception as exc:
        return tool_error(tool, exc)

    if not hits:
        return wrap_result(tool, {"found": False})

    # format_hits already wraps and escapes the passages.
    return format_hits(hits)


async def run(question: str) -> str:
    return await search_namespace(NAME, "soc", question)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Search the SOC and incident response books (NIST, network security "
        "monitoring, SOC strategy). Returns up to 3 cited passages."
    ),
    args_schema=KnowledgeArgs,
)
