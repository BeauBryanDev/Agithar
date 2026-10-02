
import hashlib
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_SENSOR_NAME_CHARS = 64
MAX_PATH_CHARS = 512
MAX_USER_AGENT_CHARS = 1024
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
HTTP_METHODS = Literal[
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "OTHER",
]


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


class EventContext(BaseModel):
    method: Optional[HTTP_METHODS] = None
    path: Optional[str] = Field(default=None, max_length=MAX_PATH_CHARS)
    user_agent_sha256: Optional[str] = None
    status: Optional[int] = Field(default=None, ge=100, le=599)

    model_config = ConfigDict(extra="forbid")

    @field_validator("path")
    @classmethod
    def strip_query(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        return value.split("?", 1)[0].split("#", 1)[0]

    @field_validator("user_agent_sha256")
    @classmethod
    def validate_hash(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not SHA256_HEX.match(value):
            raise ValueError("user_agent_sha256 must be lowercase sha256 hex")

        return value

    @classmethod
    def from_raw(
        cls,
        method: Optional[str] = None,
        target: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: Optional[int] = None,
    ) -> "EventContext":
        verb = (method or "").upper()
        agent = (user_agent or "")[:MAX_USER_AGENT_CHARS]

        return cls(
            method=verb if verb in HTTP_METHODS.__args__ else "OTHER",
            path=(target or "")[:MAX_PATH_CHARS] or None,
            user_agent_sha256=sha256_hex(agent) if agent else None,
            status=status,
        )


class SensorEventIn(BaseModel):
    source_sensor: str = Field(min_length=1, 
                               max_length=MAX_SENSOR_NAME_CHARS)
    score: float = Field(ge=0.0, le=1.0)
    is_anomalous: bool
    ip: str
    timestamp: float = Field(ge=0.0)
    detail: Optional[dict[str, Any]] = None
    context: Optional[EventContext] = None

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