from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded

NAME = "ingestion_status"

_feed: Any = None


def set_feed(feed: Any) -> None:
    # Called at startup with the running nginx feed (None when it is off).
    global _feed
    _feed = feed


class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


async def snapshot() -> dict[str, Any]:
    if _feed is None:
        return {"enabled": False}

    return _feed.snapshot()


async def run() -> str:
    return await guarded(NAME, snapshot())


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Is the live log feed running? Whether it only logs (log-only mode) "
        "or raises cases, the hosts it watches, its counters (lines read, "
        "requests scored, anomalies, rejected lines) and how many seconds "
        "ago it scored its last request."
    ),
    args_schema=NoArgs,
)
