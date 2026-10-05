from langchain_core.tools import StructuredTool

from app.agent.tools.blueteam_knowledge import KnowledgeArgs, search_namespace

NAME = "offensive_knowledge"


async def run(question: str) -> str:
    return await search_namespace(NAME, "offensive", question)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Search the attacker-side book (Linux basics for hackers) to "
        "understand how an attacker works on a Linux host. For recognising "
        "and explaining attacker behaviour only, never for writing attacks. "
        "Returns up to 3 cited passages."
    ),
    args_schema=KnowledgeArgs,
)
