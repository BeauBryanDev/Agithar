from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.net_service import get_listening_ports

NAME = "listening_ports"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME, get_listening_ports())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Read-only list of ports listening on valtoria: port, protocol, "
        "bind address, whether it is exposed on all interfaces or only on "
        "loopback, and the owning process when visible. Use it to spot "
        "services exposed by mistake. It cannot open or close anything."
    ),
    args_schema=NoArgs,
)