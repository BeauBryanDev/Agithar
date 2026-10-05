from langchain_core.tools import StructuredTool

from app.agent.tools.blueteam_knowledge import KnowledgeArgs, search_namespace

NAME = "linux_knowledge"


async def run(question: str) -> str:
    return await search_namespace(NAME, "linux-admin", question)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Search the Linux and server administration books (Debian, how "
        "Linux works). Returns up to 3 cited passages. Some commands are "
        "from older distributions; the server runs Ubuntu 24.04."
    ),
    args_schema=KnowledgeArgs,
)
