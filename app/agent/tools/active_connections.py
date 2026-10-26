from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.net_service import get_connection_summary

NAME = "active_connections"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME, get_connection_summary())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Read-only summary of TCP connections on valtoria: counts per state "
        "(ESTABLISHED, SYN_RECV, TIME_WAIT...) and the remote IPs with the "
        "most connections, marked inbound or outbound. Use it to spot scans, "
        "floods or odd outbound links, then check the remote IPs with "
        "threat_intelligence. For who is logged in, use active_sessions."
    ),
    args_schema=NoArgs,
)
