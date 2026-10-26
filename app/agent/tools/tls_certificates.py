from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.services.certs_service import get_certificates

NAME = "tls_certificates"


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def run() -> str:
    return await guarded(NAME, get_certificates())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Read-only check of the TLS certificates that nginx on this host "
        "serves for each monitored site (Basil, Florabelle, Agithar and the "
        "other projects): issuer, whether it covers the host name, expiry, "
        "trusted_until (a Cloudflare Origin certificate is trusted only "
        "while its root CA is valid), days left and status (ok, warning "
        "under 30 days, critical under 14, invalid, unreachable). It also "
        "lists sites that share one certificate. These are origin "
        "certificates behind Cloudflare and are not renewed automatically. "
        "It cannot change or renew anything."
    ),
    args_schema=NoArgs,
)
