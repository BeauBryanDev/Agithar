from typing import Any

from app.correlator.aggregation_window import WINDOW_SECONDS, Window


def build_case(
    window: Window,
    composite: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    return {
        "case_id": window.key,
        "ip": window.ip,
        "window_bucket": window.bucket,
        "window_seconds": WINDOW_SECONDS,
        "severity": decision["severity"],
        "composite_score": decision["composite_score"],
        "num_sensors": decision["num_sensors"],
        "contributing_sensors": composite["contributing_sensors"],
        "sensor_scores": composite["sensor_scores"],
        "event_counts": dict(window.counts),
        "evidence": list(window.best.values()),
    }
