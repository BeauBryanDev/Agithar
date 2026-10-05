from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.os_service import get_server_snapshot

NAME = "server_status"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME, get_server_snapshot())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Read-only health snapshot of valtoria, the server you run on: CPU, "
        "memory, disk, network counters and the state of the monitored "
        "services (Maison Roast/Basil, Florabelle, nginx, your own). Use it "
        "to check whether an attack is hurting your siblings. It cannot "
        "restart or change anything, talk to your admin on the chat."
    ),
    args_schema=NoArgs,
)
