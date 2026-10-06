
import hashlib
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.sanitize import sanitize_string

MAX_SENSOR_NAME_CHARS = 64
MAX_PATH_CHARS = 512
MAX_HOST_CHARS = 255
HOST_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,253}[a-z0-9])?$")
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
    path: Optional[str] = Field(default=None, 
                                max_length=MAX_PATH_CHARS)
    user_agent_sha256: Optional[str] = None
    status: Optional[int] = Field(default=None, ge=100, le=599)
    # The site the request was for (the Host the web server saw).
    host: Optional[str] = Field(default=None, 
                                max_length=MAX_HOST_CHARS)

    model_config = ConfigDict(extra="forbid")

    @field_validator("host", mode="before")
    @classmethod
    def clean_host(cls, value: Optional[str]) -> Optional[str]:
        # The Host header is attacker-controlled. A strange one is dropped,
        # never an error: rejecting the event would let a bad header hide it.
        if not isinstance(value, str):
            return None

        host = sanitize_string(value, MAX_HOST_CHARS).strip().lower()

        return host if HOST_NAME.match(host) else None

    @field_validator("path")
    @classmethod
    def strip_query(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        path = value.split("?", 1)[0].split("#", 1)[0]

        return sanitize_string(path, MAX_PATH_CHARS)

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
        host: Optional[str] = None,
    ) -> "EventContext":
        verb = (method or "").upper()
        agent = (user_agent or "")[:MAX_USER_AGENT_CHARS]

        return cls(
            method=verb if verb in HTTP_METHODS.__args__ else "OTHER",
            path=(target or "")[:MAX_PATH_CHARS] or None,
            user_agent_sha256=sha256_hex(agent) if agent else None,
            status=status,
            host=host,
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


MAX_BATCH_EVENTS = 100


class EventBatchIn(BaseModel):
    events: list[SensorEventIn] = Field(min_length=1,
                                        max_length=MAX_BATCH_EVENTS)

    model_config = ConfigDict(extra="forbid")


class EventResult(BaseModel):
    accepted: bool
    escalated: bool = False
    # A fixed phrase, never the rejected input.
    reason: Optional[str] = None


class EventBatchOut(BaseModel):
    accepted: int
    rejected: int
    escalated: int
    results: list[EventResult]
