from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.certs_service import get_certificates

NAME = "projects_TLS_certificates"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME,  get_certificates())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
    "Read-only check of the TLS certificates served by the monitored "
    "sites on this host: days left, expiry date and status (ok, "
    "warning under 30 days, critical under 14, invalid, unreachable). "
    "Certbot renews at 30 days left, so a warning usually means the "
    "automatic renewal is failing. It cannot renew anything."
),
    args_schema=NoArgs,
)