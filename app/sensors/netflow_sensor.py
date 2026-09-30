import math
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sensors.base import Sensor, SensorResult, load_metadata

SENSOR_NAME = "netflow_sensor"
THRESHOLD_KEY = "decision_threshold"
DUPLICATE_COLUMN = "Fwd Header Length.1"
DUPLICATE_SOURCE = "Fwd Header Length"
RATE_COLUMNS = ("Flow Bytes/s", "Flow Packets/s")
MAX_FEATURES = 256

logger = get_logger("sensors.netflow")


def read_number(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"feature '{name}' must be a number")
    return float(value)


def read_features(payload: dict[str, Any]) -> dict[str, Any]:
    features = payload.get("features")

    if not isinstance(features, dict):
        raise ValueError("payload field 'features' must be an object")

    if len(features) > MAX_FEATURES:
        raise ValueError(f"payload has more than {MAX_FEATURES} features")

    return features


def build_row(
    features: dict[str, Any],
    names: list[str],
    fallback: dict[str, float],
) -> tuple[list[float], list[str]]:
    row = []
    filled = []

    for name in names:
        source = name
        if name == DUPLICATE_COLUMN and name not in features:
            source = DUPLICATE_SOURCE

        if source not in features:
            raise ValueError(f"missing feature '{name}'")

        value = read_number(source, features[source])

        if not math.isfinite(value):
            if name not in RATE_COLUMNS:
                raise ValueError(f"feature '{name}' must be finite")
            value = fallback[name]
            filled.append(name)

        row.append(value)

    return row, filled


class NetflowSensor(Sensor):
    name = SENSOR_NAME

    def __init__(
        self,
        model_path: Path | None = None,
        scaler_path: Path | None = None,
        metadata_path: Path | None = None,
        threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        model_path = model_path or settings.netflow_model_path
        scaler_path = scaler_path or settings.netflow_scaler_path
        metadata_path = metadata_path or settings.netflow_metadata_path

        self.metadata = load_metadata(metadata_path)
        # WARNING: joblib unpickles, load only trusted local model files
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.threshold = float(threshold or self.metadata[THRESHOLD_KEY])

        self.names = list(self.scaler.feature_names_in_)
        # the training median for rate columns was never saved, use the mean
        self.fallback = dict(zip(self.names, self.scaler.mean_))

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
            features = read_features(payload)
            row, filled = build_row(features, 
                                    self.names, 
                                    self.fallback
                                    )
            
        except ValueError as exc:
            logger.warning("flow rejected: %s", exc)
            raise

        frame = pd.DataFrame([row], columns=self.names)
        scaled = self.scaler.transform(frame)
        score = float(self.model.predict_proba(scaled)[0, 1])
        is_anomalous = score >= self.threshold

        if is_anomalous:
            logger.warning(
                "anomalous flow",
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
                "filled_features": filled,
            },
        )
