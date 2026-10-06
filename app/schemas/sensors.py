from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FlaggedEvent(Strict):
    timestamp: float
    ip: str
    sensor: str
    score: float
    status: int
    path: str
    host: str


class SensorActivity(Strict):
    scored: Optional[int]
    flagged: Optional[int]
    flagged_last_hour: int
    last_flagged_at: Optional[float]
    recent: list[FlaggedEvent] = Field(max_length=10)


class SensorInfo(Strict):
    name: str
    status: str
    error: Optional[str] = None
    latency_ms: Optional[float] = None
    threshold: Optional[float] = None
    probe_score: Optional[float] = None
    purpose: str
    model: str
    trained_on: str
    sees: str
    fed_by: str
    score: str
    limits: list[str] = Field(max_length=10)
    mitre: Optional[str] = None
    correlator_weight: float
    counts_as_strong: bool
    activity: SensorActivity


class SensorsResponse(Strict):
    sampled_at: float
    all_healthy: bool
    how_cases_are_raised: str
    feed_running: bool
    sensors: list[SensorInfo]
