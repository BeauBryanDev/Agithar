import time
from typing import Any

from app.sensors.catalog import HOW_CASES_ARE_RAISED
from app.sensors.health import report
from app.sensors.registry import SensorRegistry

# The feed's counters that belong to a sensor: (scored, flagged).
FEED_COUNTERS = {
    "http_payload_sensor": ("scored_requests", "payload_anomalies"),
    "recon_sensor": ("windows_scored", "recon_anomalies"),
}


def activity(name: str, feed: Any, now: float) -> dict[str, Any]:
    # What the live feed has done with this sensor. Empty when the feed is
    # off or does not drive the sensor.
    empty = {
        "scored": None,
        "flagged": None,
        "flagged_last_hour": 0,
        "last_flagged_at": None,
        "recent": [],
    }

    if feed is None:
        return empty

    counters = feed.snapshot().get("counters", {})
    per_sensor = feed.live.by_sensor(now).get(name)
    keys = FEED_COUNTERS.get(name)

    return {
        "scored": counters.get(keys[0], 0) if keys else None,
        "flagged": counters.get(keys[1], 0) if keys else None,
        "flagged_last_hour": per_sensor["anomalies"] if per_sensor else 0,
        "last_flagged_at": per_sensor["last"] if per_sensor else None,
        "recent": per_sensor["events"] if per_sensor else [],
    }


def overview(registry: SensorRegistry, feed: Any) -> dict[str, Any]:
    now = time.time()
    sensors = report(registry)

    return {
        "sampled_at": now,
        "all_healthy": all(s["status"] == "ok" for s in sensors.values()),
        "how_cases_are_raised": HOW_CASES_ARE_RAISED,
        "feed_running": feed is not None,
        "sensors": [
            {"name": name, **state, "activity": activity(name, feed, now)}
            for name, state in sensors.items()
        ],
    }
