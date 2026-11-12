import asyncio
from typing import Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.services.sigma_service import find_rules

NAME = "detection_rules"

Platform = Literal[
    "linux",
    "web",
    "network",
    "cloud",
    "other",
    "any",
]


class DetectionRulesArgs(BaseModel):
    query: str = Field(
        min_length=2,
        max_length=120,
        description=(
            "An ATT&CK technique id such as T1053.003, a CVE id, words "
            "such as 'crontab persistence', or a rule_id from an earlier "
            "result to read that rule's full detection logic"
        ),
    )
    platform: Platform = Field(
        default="linux",
        description=(
            "Which rules to list: linux for the host, web for HTTP "
            "requests seen in web server logs, any for all of them"
        ),
    )

    model_config = ConfigDict(extra="forbid")


async def run(query: str, platform: str = "linux") -> str:
    return await guarded(NAME, asyncio.to_thread(find_rules, query, platform))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Search the public Sigma detection rules (SigmaHQ) for Linux, web, "
        "network and cloud; no Windows or macOS rules. Answers: how is "
        "this technique, CVE or behaviour detected, in which logs, and with "
        "what known false positives? Lists up to 8 rules; call again with a "
        "rule_id for the full detection logic. Reference material only: "
        "these rules are not deployed here, so a match is not evidence that "
        "something happened or that it would be detected on this server."
    ),
    args_schema=DetectionRulesArgs,
)
