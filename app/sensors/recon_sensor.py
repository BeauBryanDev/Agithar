from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sensors.base import (
    Sensor,
    SensorResult,
    load_metadata,
    read_number,
    require_str,
)

SENSOR_NAME = "recon_sensor"
THRESHOLD_KEY = "decision_threshold"
DEFAULT_THRESHOLD = 0.95
MAX_REQUESTS = 50000
MAX_PATH_CHARS = 2048
MAX_USER_AGENT_CHARS = 4096
MIN_STATUS = 100
MAX_STATUS = 599
FEATURE_NAMES = (
    "req_count",
    "ratio_404",
    "ratio_2xx",
    "unique_paths",
    "ua_count",
    "unique_path_ratio",
)

logger = get_logger("sensors.recon")


def read_status(request: dict[str, Any]) -> int:
    value = read_number("status", request.get("status"))

    if not value.is_integer() or not MIN_STATUS <= value <= MAX_STATUS:
        raise ValueError(f"status must be an integer {MIN_STATUS}-{MAX_STATUS}")

    return int(value)


def read_requests(payload: dict[str, Any]) -> list[dict[str, Any]]:
    requests = payload.get("requests")

    if not isinstance(requests, list) or not requests:
        raise ValueError("payload field 'requests' must be a non-empty list")

    if len(requests) > MAX_REQUESTS:
        raise ValueError(f"payload has more than {MAX_REQUESTS} requests")

    return requests


def build_features(payload: dict[str, Any]) -> dict[str, float]:
    paths = set()
    user_agents = set()
    count_404 = 0
    count_2xx = 0
    requests = read_requests(payload)

    for request in requests:
        if not isinstance(request, dict):
            raise ValueError("each request must be an object")

        status = read_status(request)
        paths.add(require_str(request, "path", MAX_PATH_CHARS))
        user_agents.add(
            require_str(request, "user_agent", MAX_USER_AGENT_CHARS)
        )
        count_404 += int(status == 404)
        count_2xx += int(200 <= status <= 299)

    total = len(requests)

    return {
        "req_count": total,
        "ratio_404": count_404 / total,
        "ratio_2xx": count_2xx / total,
        "unique_paths": len(paths),
        "ua_count": len(user_agents),
        "unique_path_ratio": len(paths) / total,
    }


class ReconSensor(Sensor):
    name = SENSOR_NAME

    def __init__(
        self,
        model_path: Path | None = None,
        metadata_path: Path | None = None,
        threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        model_path = model_path or settings.recon_model_path
        metadata_path = metadata_path or settings.recon_metadata_path

        self.metadata = load_metadata(metadata_path)
        # WARNING: joblib unpickles, load only trusted local model files
        self.model = joblib.load(model_path)
        self.names = list(self.metadata["features"])
        self.threshold = float(
            threshold or self.metadata.get(THRESHOLD_KEY, DEFAULT_THRESHOLD)
        )
        self.check_contract()

        logger.info(
            "sensor loaded",
            extra={
                "sensor": self.name,
                "model_file": model_path.name,
                "threshold": self.threshold,
            },
        )

    def check_contract(self) -> None:
        booster_names = list(self.model.get_booster().feature_names)

        if self.names != booster_names:
            raise ValueError("metadata features differ from the model")

        if set(self.names) != set(FEATURE_NAMES):
            raise ValueError("metadata features differ from the sensor")

    def predict(self, payload: dict[str, Any]) -> SensorResult:
        try:
            features = build_features(payload)
        except ValueError as exc:
            logger.warning("window rejected: %s", exc)
            raise

        frame = pd.DataFrame([features], columns=self.names)
        score = float(self.model.predict_proba(frame)[0, 1])
        is_anomalous = score >= self.threshold

        if is_anomalous:
            logger.warning(
                "suspicious scan window",
                extra={
                    "sensor": self.name,
                    "score": round(score, 6),
                    "threshold": self.threshold,
                },
            )

        return SensorResult(
            sensor=self.name,
            score=score,
            is_anomalous=is_anomalous,
            threshold=self.threshold,
            detail={
                "model": self.metadata.get("model"),
                "window_seconds": self.metadata.get("window_seconds"),
                "features": features,
            },
        )
