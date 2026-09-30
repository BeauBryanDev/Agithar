import math
from typing import Any

import numpy as np

from app.sensors.base import read_number

# WARNING: the training tensors went through log1p twice (the ETL cell ran
# twice), so the shipped ONNX model expects two passes, not one
LOG1P_PASSES = 2


def require_array(spec: dict[str, Any], count: int, label: str) -> np.ndarray:
    values = spec.get(label)

    if values is None or len(values) != count:
        raise ValueError(f"preprocess field '{label}' has the wrong length")

    array = np.array(values, dtype=np.float64)

    if not np.all(np.isfinite(array)):
        raise ValueError(f"preprocess field '{label}' is not finite")

    return array


class FlowPreprocessor:
    def __init__(self, spec: dict[str, Any]) -> None:
        self.names = list(spec["feature_columns"])
        count = len(self.names)

        log_names = set(spec["log1p_columns"])
        if not log_names.issubset(self.names):
            raise ValueError("log1p columns are not all feature columns")
        
        self.log_mask = np.array([n in log_names for n in self.names])

        self.lo = require_array(spec["winsorize"], count, "lo")
        self.hi = require_array(spec["winsorize"], count, "hi")
        self.center = require_array(spec["robust_scaler"], count, "center")
        self.scale = require_array(spec["robust_scaler"], count, "scale")

        if np.any(self.lo > self.hi) or np.any(self.scale == 0):
            raise ValueError("preprocess bounds or scale are invalid")

        # recovered lower bounds carry float32 noise just below zero
        floor = np.maximum(self.lo[self.log_mask], 0.0)
        self.lo[self.log_mask] = floor

    def read_row(self, features: dict[str, Any]) -> np.ndarray:
        row = []

        for name in self.names:
            if name not in features:
                raise ValueError(f"missing feature '{name}'")

            value = read_number(name, features[name])

            if math.isnan(value):
                raise ValueError(f"feature '{name}' must not be NaN")

            row.append(value)

        return np.array(row, dtype=np.float64)

    def apply_log(self, row: np.ndarray) -> np.ndarray:
        values = row.copy()
        values[self.log_mask] = np.clip(values[self.log_mask], 0.0, None)

        for _ in range(LOG1P_PASSES):
            values[self.log_mask] = np.log1p(values[self.log_mask])

        return values

    def transform(self, features: dict[str, Any]) -> np.ndarray:
        row = self.apply_log(self.read_row(features))
        row = np.clip(row, self.lo, self.hi)
        scaled = (row - self.center) / self.scale

        return scaled.astype(np.float32).reshape(1, -1)
