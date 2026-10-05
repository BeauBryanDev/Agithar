from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.services.shodan_service import check_ip

NAME = "shodan_lookup"


class ShodanArgs(BaseModel):
    ip: str = Field(max_length=45, 
                    description="One public IPv4 or IPv6")

    model_config = ConfigDict(extra="forbid")


async def run(ip: str) -> str:
    return await guarded(NAME, check_ip(ip))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Shodan host lookup for one IP: open ports, services and known "
        "vulnerabilities as Shodan last saw them. Passive: it reads Shodan's "
        "database and scans nothing. found=false means Shodan has no data."
    ),
    args_schema=ShodanArgs,
)
