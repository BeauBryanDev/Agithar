from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort

from app.core.config import get_settings
from app.core.logging import get_logger
from app.sensors.base import (
    Sensor,
    SensorResult,
    load_metadata,
    read_features,
)
from app.sensors.net_guard_preprocess import FlowPreprocessor


SENSOR_NAME = "cnn1d_b"
BENIGN_CLASS = "BENIGN"
MAX_FEATURES = 256
PROBABILITY_DIGITS = 6

logger = get_logger("sensors.net_guard")


def softmax(logits: np.ndarray) -> np.ndarray:
    shifted = np.exp(logits - np.max(logits))
    return shifted / shifted.sum()


class NetGuardSensor(Sensor):
    name = SENSOR_NAME

    def __init__(
        self,
        model_path: Path | None = None,
        metadata_path: Path | None = None,
        preprocess_path: Path | None = None,
    ) -> None:
        settings = get_settings()
        model_path = model_path or settings.netguard_model_path
        metadata_path = metadata_path or settings.netguard_metadata_path
        preprocess_path = preprocess_path or settings.netguard_preprocess_path

        self.metadata = load_metadata(metadata_path)
        self.class_names = list(self.metadata["class_names"])
        self.benign_index = self.class_names.index(BENIGN_CLASS)
        self.preprocessor = FlowPreprocessor(load_metadata(preprocess_path))

        self.session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.check_contract()

        logger.info(
            "sensor loaded",
            extra={"sensor": self.name, "model_file": model_path.name},
        )

    def check_contract(self) -> None:
        input_width = self.session.get_inputs()[0].shape[1]
        output_width = self.session.get_outputs()[0].shape[1]

        if input_width != len(self.preprocessor.names):
            raise ValueError("preprocess and ONNX feature counts differ")

        if output_width != len(self.class_names):
            raise ValueError("metadata classes and ONNX outputs differ")


    def predict(self, payload: dict[str, Any]) -> SensorResult:
        try:
            features = read_features(payload, MAX_FEATURES)
            batch = self.preprocessor.transform(features)
            
        except ValueError as exc:
            logger.warning("flow rejected: %s", exc)
            raise

        logits = self.session.run(None, {self.input_name: batch})[0][0]
        probabilities = softmax(logits.astype(np.float64))

        top_index = int(np.argmax(probabilities))
        predicted = self.class_names[top_index]
        score = float(1.0 - probabilities[self.benign_index])
        is_anomalous = top_index != self.benign_index

        if is_anomalous:
            logger.warning(
                "anomalous flow",
                extra={
                    "sensor": self.name,
                    "predicted_class": predicted,
                    "score": round(score, 6),
                },
            )

        return SensorResult(
            sensor=self.name,
            score=score,
            is_anomalous=is_anomalous,
            threshold=None,
            detail={
                "model": self.metadata.get("model_name"),
                "predicted_class": predicted,
                "confidence": round(
                    float(probabilities[top_index]), PROBABILITY_DIGITS
                ),
                "class_probabilities": self.round_probabilities(
                    probabilities
                ),
            },
        )

    def round_probabilities(
        self,
        probabilities: np.ndarray,
    ) -> dict[str, float]:
        rounded = {}

        for name, value in zip(self.class_names, probabilities):
            rounded[name] = round(float(value), PROBABILITY_DIGITS)

        return rounded
