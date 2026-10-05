import asyncio
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.db.postgresql.repository import list_incidents_by_ip
from app.db.postgresql.session import get_session_factory
from app.utils.network import normalize_ip

NAME = "incident_history"
MAX_ITEMS = 10


class HistoryError(Exception):
    pass


class HistoryArgs(BaseModel):
    ip: str = Field(max_length=45, description="One IPv4 or IPv6 address")

    model_config = ConfigDict(extra="forbid")


def incident_row(item: Any) -> dict[str, Any]:
    # Past verdict names only: free text from old cases is not replayed.
    return {
        "incident_id": item.incident_id,
        "ip": item.ip,
        "severity": item.severity,
        "status": item.status,
        "composite_score": item.composite_score,
        "sensors": item.contributing_sensors,
        "mitre": (item.verdict or {}).get("mitre_technique"),
        "created_at": item.created_at,
    }


def fetch(ip: str) -> dict[str, Any]:
    try:
        clean_ip = normalize_ip(ip)

    except ValueError:
        raise HistoryError("invalid ip address") from None

    with get_session_factory()() as session:
        items, total = list_incidents_by_ip(session, clean_ip, 0, MAX_ITEMS)

        rows = [incident_row(item) for item in items]

    return {"ip": clean_ip, "total": total, "latest": rows}


async def run(ip: str) -> str:
    return await guarded(NAME, asyncio.to_thread(fetch, ip))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Our own earlier incidents for one IP (newest first, up to 10): "
        "severity, status, sensors, MITRE technique and date. Repeat "
        "offenders matter: check it before deciding on a verdict."
    ),
    args_schema=HistoryArgs,
)
