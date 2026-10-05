from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from app.core.logging import get_logger
from app.rag import mitre_attack
from app.schemas.dashboard import (
    DashboardData,
    SensorCount,
    TechniqueCount,
    TimelinePoint,
)

logger = get_logger("services.dashboard")

HOUR = 3600
DAY = 86400
MAX_TOP = 8
SEVERITIES = ("low", "medium", "high")
STATUSES = ("open", "confirmed", "false_positive", "needs_human", "closed")
# Up to two days the timeline has one point per hour, beyond that per day.
HOURLY_LIMIT_HOURS = 48


def as_utc(moment: datetime) -> datetime:
    # SQLite returns naive datetimes; PostgreSQL returns aware ones.
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)

    return moment.astimezone(timezone.utc)


def bucket_seconds(hours: int) -> int:
    return HOUR if hours <= HOURLY_LIMIT_HOURS else DAY


def floor_to(moment: datetime, seconds: int) -> datetime:
    epoch = int(moment.timestamp())

    return datetime.fromtimestamp(epoch - epoch % seconds, tz=timezone.utc)


def build_timeline(
    rows: list[Any], now: datetime, hours: int
) -> list[TimelinePoint]:
    size = bucket_seconds(hours)
    start = floor_to(now - timedelta(hours=hours), size)
    end = floor_to(now, size)
    best: dict[datetime, float] = {}
    count: Counter[datetime] = Counter()

    for row in rows:
        key = floor_to(as_utc(row.created_at), size)
        best[key] = max(best.get(key, 0.0), float(row.composite_score))
        count[key] += 1

    points = []
    moment = start

    while moment <= end:
        score = min(max(best.get(moment, 0.0), 0.0), 1.0)
        points.append(
            TimelinePoint(
                timestamp=moment, score=score, incidents=count[moment]
            )
        )
        moment += timedelta(seconds=size)

    return points


def technique_name(technique: str) -> str | None:
    try:
        entry = mitre_attack.lookup(technique)

    except mitre_attack.MitreError:
        return None

    return entry["name"] if entry else None


def verdict_of(row: Any) -> dict[str, Any]:
    return row.verdict if isinstance(row.verdict, dict) else {}


def mean_confidence(rows: list[Any]) -> float | None:
    values = [
        verdict_of(row).get("confidence")
        for row in rows
        if isinstance(verdict_of(row).get("confidence"), (int, float))
    ]

    if not values:
        return None

    return round(min(max(sum(values) / len(values), 0.0), 1.0), 4)


def build_dashboard(
    rows: Iterable[Any],
    now: datetime,
    hours: int,
    truncated: bool = False,
) -> DashboardData:
    items = list(rows)
    severity = Counter(row.severity for row in items)
    status = Counter(row.status for row in items)
    sensors = Counter(
        name for row in items for name in (row.contributing_sensors or [])
    )
    techniques = Counter(
        verdict_of(row).get("mitre_technique")
        for row in items
        if verdict_of(row).get("mitre_technique")
    )

    return DashboardData(
        window_hours=hours,
        total_incidents=len(items),
        truncated=truncated,
        severity_distribution={name: severity[name] for name in SEVERITIES},
        status_counts={name: status[name] for name in STATUSES},
        avg_confidence=mean_confidence(items),
        timeline=build_timeline(items, now, hours),
        by_sensor=[
            SensorCount(sensor=name, count=total)
            for name, total in sensors.most_common(MAX_TOP)
        ],
        top_techniques=[
            TechniqueCount(
                technique=name, name=technique_name(name), count=total
            )
            for name, total in techniques.most_common(MAX_TOP)
        ],
    )
