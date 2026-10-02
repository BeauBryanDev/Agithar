from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit

import joblib

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sensors.base import (
    Sensor,
    SensorResult,
    load_metadata,
    require_str,
)

SENSOR_NAME = "http_payload_sensor"
HTTP_VERSION_MARKER = " HTTP/"
MAX_FIELD_CHARS = 65536
THRESHOLD_KEY = "decision_threshold"

logger = get_logger("sensors.http_payload")


def strip_http_version(url: str) -> str:
    return url.rsplit(HTTP_VERSION_MARKER, 1)[0]


def strip_host(url: str) -> str:
    parts = urlsplit(url)
    if parts.query:
        return f"{parts.path}?{parts.query}"
    return parts.path


def build_text(path_query: str, body: str) -> str:
    return unquote_plus(unquote_plus(f"{path_query} {body}")).lower()


def extract_fields(payload: dict[str, Any]) -> tuple[str, str]:
    url = require_str(payload, "url", MAX_FIELD_CHARS)
    body = payload.get("body") or ""

    if not isinstance(body, str) or len(body) > MAX_FIELD_CHARS:
        raise ValueError("payload field 'body' is invalid")

    return url, body


def prepare_text(payload: dict[str, Any]) -> str:
    url, body = extract_fields(payload)
    path_query = strip_host(strip_http_version(url))
    
    return build_text(path_query, body)


class HttpPayloadSensor(Sensor):
    name = SENSOR_NAME

    def __init__(
        self,
        model_path: Path | None = None,
        metadata_path: Path | None = None,
        threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        model_path = model_path or settings.http_payload_model_path
        metadata_path = metadata_path or settings.http_payload_metadata_path

        self.metadata = load_metadata(metadata_path)
        # WARNING: joblib unpickles, load only trusted local model files
        self.pipeline = joblib.load(model_path)
        self.threshold = float(threshold or self.metadata[THRESHOLD_KEY])

        logger.info(
            "sensor loaded",
            extra={
                "sensor": self.name,
                "model_file": model_path.name,
                "threshold": self.threshold,
            },
        )

    def predict(self, payload: dict[str, Any]) -> SensorResult:
        try:
            text = prepare_text(payload)
            
        except ValueError as exc:
            logger.warning("payload rejected: %s", exc)
            raise

        score = float(self.pipeline.predict_proba([text])[0, 1])
        is_anomalous = score >= self.threshold

        if is_anomalous:
            logger.warning(
                "anomalous payload",
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
            detail={"model": self.metadata.get("model")},
        )
