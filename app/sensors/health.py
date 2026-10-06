import math
import time
from typing import Any

import numpy as np

from app.sensors.registry import SENSOR_CLASSES, SensorRegistry


class SensorHealthError(Exception):
    # Kept as an app error so its fixed text reaches the agent.
    pass


# Harmless inputs that exercise each model end to end. They prove the model
# loads and runs; they say nothing about its accuracy.
PROBE_EVENTS = ["E5", "E22", "E11", "E9", "E26", "E26", "E26"]
PROBE_REQUESTS = [
    {"path": "/", "status": 200, "user_agent": "health-probe"},
    {"path": "/products/", "status": 200, "user_agent": "health-probe"},
]


def median_flow(preprocessor: Any) -> dict[str, float]:
    # The training median of every feature (the scaler centre, with the
    # double log1p undone): a typical benign flow.
    row = {}

    for name, centre, logged in zip(
        preprocessor.names, preprocessor.center, preprocessor.log_mask
    ):
        value = np.expm1(np.expm1(centre)) if logged else centre
        row[name] = float(value)

    return row


def probe_payload(name: str, sensor: Any) -> dict[str, Any]:
    if name == "http_payload_sensor":
        return {"url": "/products/"}

    if name == "recon_sensor":
        return {"requests": PROBE_REQUESTS}

    if name == "log_sentinel":
        return {"events": PROBE_EVENTS, "block_id": "health-probe"}

    if name == "net_guard":
        return {"features": median_flow(sensor.preprocessor)}

    if name == "netflow_sensor":
        # The scaler mean is an average flow: benign, so no alert is logged.
        return {"features": dict(sensor.fallback)}

    raise KeyError(name)


def probe_one(registry: SensorRegistry, name: str) -> dict[str, Any]:
    sensor = registry.get(name)
    started = time.perf_counter()

    try:
        result = sensor.predict(probe_payload(name, sensor))

    except Exception as exc:
        # Only the class name: the text can hold paths.
        return {"status": "error", "error": type(exc).__name__}

    millis = round((time.perf_counter() - started) * 1000, 1)
    score = result.score
    valid = (
        isinstance(score, float)
        and math.isfinite(score)
        and 0.0 <= score <= 1.0
    )

    return {
        "status": "ok" if valid else "bad_output",
        "latency_ms": millis,
        "threshold": getattr(sensor, "threshold", None),
        "probe_score": round(score, 4) if valid else None,
    }


def check_all(registry: SensorRegistry) -> dict[str, dict[str, Any]]:
    # Every expected sensor appears: one that failed to load is reported as
    # such (by class name; the load error text is never exposed).
    out: dict[str, dict[str, Any]] = {}
    failed_classes = set(registry.failures)

    for sensor_class in SENSOR_CLASSES:
        name = sensor_class.name

        if name in registry.sensors:
            out[name] = probe_one(registry, name)

        elif sensor_class.__name__ in failed_classes:
            out[name] = {"status": "failed_to_load"}

        else:
            out[name] = {"status": "missing"}

    return out


def report(registry: SensorRegistry) -> dict[str, dict[str, Any]]:
    # Probe result plus the static profile, per expected sensor.
    from app.sensors import catalog

    health = check_all(registry)

    return {
        name: {**state, **catalog.profile_for(name)}
        for name, state in health.items()
    }
