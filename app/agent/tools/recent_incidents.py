import asyncio
from typing import Any, Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict

from app.agent.tools.common import guarded
from app.agent.tools.incident_history import MAX_ITEMS, incident_row
from app.db.postgresql.repository import list_incidents_by_severity
from app.db.postgresql.session import get_session_factory

NAME = "recent_incidents"


class RecentArgs(BaseModel):
    severity: Literal["low", "medium", "high"]

    model_config = ConfigDict(extra="forbid")


def fetch(severity: str) -> dict[str, Any]:
    
    with get_session_factory()() as session:
        items, total = list_incidents_by_severity(
            session, severity, 0, MAX_ITEMS
        )
        rows = [incident_row(item) for item in items]

    return {
        "severity": severity, 
        "total": total, 
        "latest": rows
        }


async def run(severity: str) -> str:
    return await guarded(NAME, asyncio.to_thread(fetch, severity))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Our latest incidents of one severity (up to 10, newest first) across "
        "all IPs. Use it to see whether this case is part of a wider wave"
        "it is important to give reports to your admin when he is on the chat"
    ),
    args_schema=RecentArgs,
)
