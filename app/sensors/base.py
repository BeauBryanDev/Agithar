import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MODELS_DIR = Path(__file__).resolve().parents[2] / "models"


@dataclass(frozen=True)
class SensorResult:
    sensor: str
    score: float
    is_anomalous: bool
    threshold: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_event(self) -> dict[str, Any]:
        return {
            "source_sensor": self.sensor,
            "score": self.score,
            "is_anomalous": self.is_anomalous,
            "threshold": self.threshold,
            "detail": self.detail,
        }


class Sensor(ABC):
    name: str

    @abstractmethod
    def predict(self, payload: dict[str, Any]) -> SensorResult:
        pass


def load_metadata(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def require_str(payload: dict[str, Any], 
                key: str, 
                max_chars: int
                ) -> str:
    
    value = payload.get(key)
    
    if not isinstance(value, str):
        raise ValueError(f"payload field '{key}' must be a string")
    
    if len(value) > max_chars:
        raise ValueError(f"payload field '{key}' exceeds {max_chars} chars")
    
    return value
