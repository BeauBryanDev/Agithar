from typing import Any

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}
MULTI_SENSOR_SCORE = 0.6
SOLO_SENSOR_SCORE = 0.9
MANY_SENSORS = 3
MANY_SENSORS_SCORE = 0.4


def classify(composite: dict[str, Any]) -> str:
    score = composite["composite_score"]
    # weak sensors are left out of the count, so they cannot escalate alone
    count = composite["num_strong_sensors"]

    if count >= 2 and score >= MULTI_SENSOR_SCORE:
        return "high"

    if count == 1 and score >= SOLO_SENSOR_SCORE:
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
        "num_strong_sensors": composite["num_strong_sensors"],
    }
