from pydantic import BaseModel, ConfigDict, Field


class LiveEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: float
    ip: str
    sensor: str
    score: float
    status: int
    path: str
    host: str


class MinutePoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minute: int
    requests: int
    anomalies: int


class TopIp(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    count: int
    max_score: float
    sensors: list[str] = Field(max_length=10)


class TopPath(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    count: int


class LiveResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    log_only: bool
    events: list[LiveEvent] = Field(max_length=200)
    per_minute: list[MinutePoint] = Field(max_length=120)
    top_ips: list[TopIp] = Field(max_length=20)
    top_paths: list[TopPath] = Field(max_length=20)
    anomalies_in_window: int
    window_minutes: int
