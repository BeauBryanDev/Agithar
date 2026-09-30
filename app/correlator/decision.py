from typing import Any

from app.correlator.scoring import weight_for

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
MULTI_SENSOR_SCORE = 0.6
SOLO_SENSOR_SCORE = 0.9
MANY_SENSORS = 3
MANY_SENSORS_SCORE = 0.4
# a lone sensor below this weight can never escalate on its own
MIN_SOLO_WEIGHT = 0.5


def classify(composite: dict[str, Any]) -> str:
    score = composite["composite_score"]
    count = composite["num_sensors"]

    if count >= 2 and score >= MULTI_SENSOR_SCORE:
        return "high"

    if count == 1 and score >= SOLO_SENSOR_SCORE:
        sensor = composite["contributing_sensors"][0]
        if weight_for(sensor) >= MIN_SOLO_WEIGHT:
            return "medium"

    if count >= MANY_SENSORS and score >= MANY_SENSORS_SCORE:
        return "high"

    return "low"


def decide(composite: dict[str, Any]) -> dict[str, Any]:
    severity = classify(composite)

    return {
        "escalate": severity != "low",
        "severity": severity,
        "composite_score": composite["composite_score"],
        "num_sensors": composite["num_sensors"],
    }
