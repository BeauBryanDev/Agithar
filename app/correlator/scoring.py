from typing import Any

WEIGHTS = {
    "sensor_payload": 1.0,
    "netflow_sensor": 1.0,
    "cnn1d_a": 0.8,
    "cnn1d_b": 0.8,
    "recon_sensor": 0.2,
}
DEFAULT_WEIGHT = 0.5


def weight_for(sensor: str) -> float:
    return WEIGHTS.get(sensor, DEFAULT_WEIGHT)


def compute_composite(best: dict[str, dict[str, Any]]) -> dict[str, Any]:
    total_weight = 0.0
    weighted_sum = 0.0
    sensor_scores = {}

    for sensor, event in best.items():
        weight = weight_for(sensor)
        weighted_sum += event["score"] * weight
        total_weight += weight
        sensor_scores[sensor] = event["score"]

    composite = weighted_sum / total_weight if total_weight > 0 else 0.0

    return {
        "composite_score": composite,
        "num_sensors": len(best),
        "contributing_sensors": sorted(best),
        "sensor_scores": sensor_scores,
    }
