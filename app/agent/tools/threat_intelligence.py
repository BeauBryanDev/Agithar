import asyncio

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import describe_error, wrap_result
from app.services import abuse_ip_service, ip_geo_loc, virustotal_service

NAME = "threat_intelligence"

# Shodan is left out on purpose: it is only for our own servers.
SOURCES = {
    "abuseipdb": abuse_ip_service.check_ip,
    "virustotal": virustotal_service.check_ip,
    "geolocation": ip_geo_loc.geo_lookup,
}


class ThreatArgs(BaseModel):
    ip: str = Field(max_length=45, description="One IPv4 or IPv6 address")

    model_config = ConfigDict(extra="forbid")


async def run(ip: str) -> str:
    results = await asyncio.gather(
        *(check(ip) for check in SOURCES.values()), return_exceptions=True
    )
    data = {}

    for name, result in zip(SOURCES, results):
        failed = isinstance(result, Exception)
        data[name] = {"error": describe_error(result)} if failed else result

    return wrap_result(NAME, data)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Reputation of one IP address from AbuseIPDB and VirusTotal, plus "
        "its geolocation. A source that fails reports its own error. Use "
        "once per IP: the free quotas are small."
    ),
    args_schema=ThreatArgs,
)
