import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.agent.tools.shops import ShopName, shop_of_evidence
from app.db.postgresql import repository
from app.db.postgresql.session import get_session_factory

NAME = "shop_incidents"
MAX_ROWS = 15


class IncidentsArgs(BaseModel):
    shop: ShopName
    hours: int = Field(default=24, ge=1, le=720)

    model_config = ConfigDict(extra="forbid")


def row_view(row: Any, shop: str) -> dict[str, Any]:
    verdict = row.verdict if isinstance(row.verdict, dict) else {}

    return {
        "incident_id": row.incident_id,
        "shop": shop,
        "ip": row.ip,
        "severity": row.severity,
        "status": row.status,
        "score": round(float(row.composite_score), 3),
        "sensors": list(row.contributing_sensors or []),
        "mitre": verdict.get("mitre_technique"),
        "confidence": verdict.get("confidence"),
        "created_at": row.created_at,
        "admin_alerted": bool(row.notified),
    }


def compute(shop: str, hours: int) -> dict[str, Any]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    with get_session_factory()() as session:
        rows = repository.incidents_with_evidence_since(session, since)

    labelled = [(row, shop_of_evidence(row.evidence)) for row in rows]
    chosen = [
        (row, name) for row, name in labelled
        if shop == "all" or name == shop
    ]

    return {
        "shop": shop,
        "window_hours": hours,
        "total": len(chosen),
        "by_status": dict(Counter(row.status for row, _ in chosen)),
        "by_shop": dict(Counter(name for _, name in chosen)),
        "latest": [row_view(row, name) for row, name in chosen[:MAX_ROWS]],
        "note": "incidents without a recorded host count as 'unknown'",
    }


async def run(shop: str, hours: int = 24) -> str:
    return await guarded(NAME, asyncio.to_thread(compute, shop, hours))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Incidents the sensors raised for one shop (or all) in the last "
        "hours: counts by status and shop, and the newest ones with IP, "
        "severity, status, sensors and the master's MITRE technique and "
        "confidence once it has a verdict."
    ),
    args_schema=IncidentsArgs,
)
