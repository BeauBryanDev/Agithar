import ipaddress
import math
import threading
from typing import Any

from app.core.logging import get_logger
from app.correlator.aggregation_window import WindowStore
from app.correlator.decision import SEVERITY_RANK, decide
from app.correlator.escalate2master import build_case
from app.correlator.scoring import compute_composite
from app.schemas.events import EventContext
from app.security.sanitize import sanitize_detail
from app.sensors.base import SensorResult

MAX_SENSOR_NAME_CHARS = 64

logger = get_logger("correlator")


def event_from_result(
    result: SensorResult,
    ip: str,
    timestamp: float,
) -> dict[str, Any]:
    event = result.to_event()
    event["ip"] = ip
    event["timestamp"] = timestamp

    return event


def read_ip(event: dict[str, Any]) -> str:
    value = event.get("ip")

    if not isinstance(value, str):
        raise ValueError("event field 'ip' must be a string")

    try:
        return str(ipaddress.ip_address(value))
    
    except ValueError as exc:
        raise ValueError("event field 'ip' is not a valid address") from exc


def read_timestamp(event: dict[str, Any]) -> float:
    value = event.get("timestamp")

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("event field 'timestamp' must be a number")

    if not math.isfinite(value) or value < 0:
        raise ValueError("event field 'timestamp' must be finite and >= 0")

    return float(value)


def read_score(event: dict[str, Any]) -> float:
    value = event.get("score")

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("event field 'score' must be a number")

    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ValueError("event field 'score' must be between 0 and 1")

    return float(value)


def read_context(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("context")

    if value is None:
        return {}

    return EventContext.model_validate(value).model_dump(exclude_none=True)


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    sensor = event.get("source_sensor")

    if not isinstance(sensor, str) or not sensor:
        raise ValueError("event field 'source_sensor' must be a string")

    if len(sensor) > MAX_SENSOR_NAME_CHARS:
        raise ValueError("event field 'source_sensor' is too long")

    if not isinstance(event.get("is_anomalous"), bool):
        raise ValueError("event field 'is_anomalous' must be a boolean")

    return {
        "source_sensor": sensor,
        "score": read_score(event),
        "is_anomalous": event["is_anomalous"],
        "ip": read_ip(event),
        "timestamp": read_timestamp(event),
        "detail": sanitize_detail(event.get("detail") or {}),
        "context": read_context(event),
    }


class Correlator:
    def __init__(
        self, store: WindowStore | None = None) -> None:
        self.store = store or WindowStore()
        self.lock = threading.Lock()

    def stats(self) -> dict[str, int]:
        with self.lock:
            return {"open_windows": len(self.store.windows)}

    def ingest(self, event: dict[str, Any]) -> dict[str, Any] | None:
        try:
            clean = normalize_event(event)
            
        except ValueError as exc:
            logger.warning("event rejected: %s", exc)
            raise

        if not clean["is_anomalous"]:
            return None

        with self.lock:
            window = self.store.add(clean)
            composite = compute_composite(window.best)
            decision = decide(composite)
            rank = SEVERITY_RANK[decision["severity"]]

            if not decision["escalate"] or rank <= window.escalated_rank:
                return None

            window.escalated_rank = rank
            case = build_case(window, composite, decision)

        logger.warning(
            "escalating to master agent",
            extra={
                "case_id": case["case_id"],
                "severity": case["severity"],
                "composite_score": round(case["composite_score"], 4),
                "sensors": ",".join(case["contributing_sensors"]),
            },
        )

        return case
