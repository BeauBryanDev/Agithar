from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.sessions_service import get_sessions


NAME = "active_connections"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME,  get_sessions()) 


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
    "Read-only view of who is on valtoria right now: logged-in users "
    "with terminal, origin host and start time, plus established SSH "
    "connections on port 22. Users outside the expected list are "
    "flagged, and ssh_exceeds_sessions warns of SSH connections with no "
    "terminal (tunnels, sftp). Check remote IPs with threat_intelligence."
),
    args_schema=NoArgs,
)