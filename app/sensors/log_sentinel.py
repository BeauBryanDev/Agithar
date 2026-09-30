import math
import re
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sensors.base import Sensor, SensorResult, load_metadata

SENSOR_NAME = "cnn1d_a" # logsentinel 
PAD_ID = 0
UNKNOWN_TOKEN = "<UNK>"
MAX_EVENTS = 10000
MAX_TOKEN_CHARS = 32
MAX_LOGIT = 60.0
BLOCK_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

logger = get_logger("sensors.log_sentinel")


def sigmoid(logit: float) -> float:
    clipped = max(-MAX_LOGIT, min(MAX_LOGIT, logit))
    return 1.0 / (1.0 + math.exp(-clipped))


def read_events(payload: dict[str, Any]) -> list[str]:
    events = payload.get("events")

    if not isinstance(events, list) or not events:
        raise ValueError("payload field 'events' must be a non-empty list")

    if len(events) > MAX_EVENTS:
        raise ValueError(f"payload has more than {MAX_EVENTS} events")

    for event in events:
        if not isinstance(event, str) or len(event) > MAX_TOKEN_CHARS:
            raise ValueError("every event must be a short string")

    return events


def read_block_id(payload: dict[str, Any]) -> str | None:
    block_id = payload.get("block_id")

    if block_id is None:
        return None

    if not isinstance(block_id, str) or not BLOCK_ID_PATTERN.match(block_id):
        raise ValueError("payload field 'block_id' is invalid")

    return block_id


def encode_events(
    events: list[str],
    vocab: dict[str, int],
    max_len: int,
) -> tuple[list[int], int]:
    unknown_id = vocab[UNKNOWN_TOKEN]
    ids = []
    unknown = 0

    for event in events[:max_len]:
        if event in vocab and event != UNKNOWN_TOKEN:
            ids.append(vocab[event])
        else:
            ids.append(unknown_id)
            unknown += 1

    ids.extend([PAD_ID] * (max_len - len(ids)))

    return ids, unknown


class LogSentinelSensor(Sensor):
    name = SENSOR_NAME

    def __init__(
        self,
        model_path: Path | None = None,
        metadata_path: Path | None = None,
        threshold: float | None = None,
    ) -> None:
        settings = get_settings()
        model_path = model_path or settings.logsentinel_model_path
        metadata_path = metadata_path or settings.logsentinel_metadata_path

        self.metadata = load_metadata(metadata_path)
        contract = self.metadata["input_contract"]
        self.vocab = contract["vocab"]
        self.max_len = int(contract["shape"][1])
        self.threshold = float(
            threshold or self.metadata["threshold"]["value"]
        )

        self.session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.check_contract() # check contract compatibility

        logger.info(
            "sensor loaded",
            extra={
                "sensor": self.name,
                "model_file": model_path.name,
                "threshold": self.threshold,
            },
        )

    def check_contract(self) -> None:
        onnx_len = self.session.get_inputs()[0].shape[1]

        if UNKNOWN_TOKEN not in self.vocab:
            raise ValueError("metadata vocab has no unknown token")

        if PAD_ID in self.vocab.values():
            raise ValueError("metadata vocab uses the padding id")

        if onnx_len != self.max_len:
            raise ValueError("metadata and ONNX sequence length differ")

    def predict(self, payload: dict[str, Any]) -> SensorResult:
        try:
            events = read_events(payload)
            block_id = read_block_id(payload)
        except ValueError as exc:
            logger.warning("sequence rejected: %s", exc)
            raise

        ids, unknown = encode_events(events, self.vocab, self.max_len)
        batch = np.array([ids], dtype=np.int64)
        logit = self.session.run(None, {self.input_name: batch})[0]
        score = sigmoid(float(logit[0][0]))
        is_anomalous = score >= self.threshold

        if is_anomalous:
            logger.warning(
                "anomalous log sequence",
                extra={
                    "sensor": self.name,
                    "score": round(score, 6),
                    "threshold": self.threshold,
                    "block_id": block_id,
                },
            )

        return SensorResult(
            sensor=self.name,
            score=score,
            is_anomalous=is_anomalous,
            threshold=self.threshold,
            detail={
                "model": self.metadata.get("model_name"),
                "block_id": block_id,
                "events_seen": len(events),
                "truncated": len(events) > self.max_len,
                "unknown_events": unknown,
            },
        )
