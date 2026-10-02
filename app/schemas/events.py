
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_SENSOR_NAME_CHARS = 64


class SensorEventIn(BaseModel):
    source_sensor: str = Field(min_length=1, 
                               max_length=MAX_SENSOR_NAME_CHARS)
    score: float = Field(ge=0.0, le=1.0)
    is_anomalous: bool
    ip: str
    timestamp: float = Field(ge=0.0)
    detail: Optional[dict[str, Any]] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        import ipaddress

        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("ip is not a valid address") from exc

    def __repr__(self) -> str:
        return f"SensorEventIn(source_sensor={self.source_sensor!r}, ip={self.ip!r})"


class EventAccepted(BaseModel):
    accepted: bool
    escalated: bool


class EventRejected(BaseModel):
    accepted: bool = False
    reason: str