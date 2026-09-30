import math
from pathlib import Path
from typing import Any

import joblib
import numpy as np
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
# metadata has no tuned threshold, its metrics are at the 0.5 default
DEFAULT_THRESHOLD = 0.5
PROTOCOLS = ("ICMP", "TCP", "UDP")
MAX_PORT = 65535
MAX_USER_AGENT_CHARS = 4096
SUSPICIOUS_UA_KEYWORDS = (
    "curl",
    "python-requests",
    "python-urllib",
    "sqlmap",
    "zgrab",
    "nmap",
    "nikto",
    "masscan",
)
FEATURE_NAMES = (
    "src_port",
    "dst_port",
    "log_bytes_sent",
    "log_bytes_received",
    "is_internal_traffic",
    "ua_is_suspicious_tool",
    "ua_length",
    "proto_ICMP",
    "proto_TCP",
    "proto_UDP",
)

logger = get_logger("sensors.recon")


def get_field(payload: dict[str, Any], key: str) -> Any:
    if key not in payload:
        raise ValueError(f"missing field '{key}'")

    return payload[key]


def read_port(payload: dict[str, Any], key: str) -> int:
    value = read_number(key, get_field(payload, key))

    if not value.is_integer() or not 0 <= value <= MAX_PORT:
        raise ValueError(f"field '{key}' must be a port from 0 to {MAX_PORT}")

    return int(value)


def read_bytes(payload: dict[str, Any], key: str) -> float:
    value = read_number(key, get_field(payload, key))

    if not math.isfinite(value) or value < 0:
        raise ValueError(f"field '{key}' must be a finite number >= 0")

    return value


def read_flag(payload: dict[str, Any], key: str) -> bool:
    value = get_field(payload, key)

    if not isinstance(value, bool):
        raise ValueError(f"field '{key}' must be a boolean")

    return value


def read_protocol(payload: dict[str, Any]) -> str:
    protocol = require_str(payload, "protocol", 16).upper()

    if protocol not in PROTOCOLS:
        raise ValueError(f"field 'protocol' must be one of {PROTOCOLS}")

    return protocol


def is_suspicious_tool(user_agent: str) -> bool:
    lowered = user_agent.lower()

    for keyword in SUSPICIOUS_UA_KEYWORDS:
        if keyword in lowered:
            return True

    return False


def build_features(payload: dict[str, Any]) -> dict[str, float]:
    user_agent = require_str(payload, "user_agent", MAX_USER_AGENT_CHARS)
    protocol = read_protocol(payload)

    return {
        "src_port": read_port(payload, "src_port"),
        "dst_port": read_port(payload, "dst_port"),
        "log_bytes_sent": math.log1p(read_bytes(payload, "bytes_sent")),
        "log_bytes_received": math.log1p(
            read_bytes(payload, "bytes_received")
        ),
        "is_internal_traffic": int(read_flag(payload, "is_internal_traffic")),
        "ua_is_suspicious_tool": int(is_suspicious_tool(user_agent)),
        "ua_length": len(user_agent),
        "proto_ICMP": int(protocol == "ICMP"),
        "proto_TCP": int(protocol == "TCP"),
        "proto_UDP": int(protocol == "UDP"),
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
            logger.warning("connection rejected: %s", exc)
            raise

        frame = pd.DataFrame([features], columns=self.names)
        score = float(self.model.predict_proba(frame)[0, 1])
        is_anomalous = score >= self.threshold

        if is_anomalous:
            logger.warning(
                "suspicious connection",
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
                "features": features,
            },
        )
