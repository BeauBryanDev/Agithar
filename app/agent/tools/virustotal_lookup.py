from typing import Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.services.virustotal_service import check_hash, check_url

NAME = "virustotal_lookup"
CHECKS = {"hash": check_hash, "url": check_url}


class VirusTotalArgs(BaseModel):
    kind: Literal["hash", "url"]
    value: str = Field(
        max_length=2048,
        description="An md5, sha1 or sha256 hex hash, or an http(s) URL",
    )

    model_config = ConfigDict(extra="forbid")


async def run(kind: str, value: str) -> str:
    return await guarded(NAME, CHECKS[kind](value))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "VirusTotal reputation of a file hash or a URL seen in the evidence "
        "(for an IP use threat_intelligence). Returns detection counts only; "
        "the URL is not echoed back. The free quota is 4 requests a minute."
    ),
    args_schema=VirusTotalArgs,
)
