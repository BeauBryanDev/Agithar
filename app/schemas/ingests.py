from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SEVERITY = Literal["low", "medium", "high"]
KIND = Literal["access_log", "event_ids", "flow_csv"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SensorStat(Strict):
    sensor: str
    scored: int
    flagged: int
    max_score: float


class SourceSummary(Strict):
    source: str
    severity: SEVERITY
    composite_score: float
    sensors: list[str] = Field(max_length=10)
    items: int
    flagged: int


class Finding(Strict):
    sensor: str
    score: float
    source: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    count: int = 1
    detail: Optional[str] = None
    time: Optional[float] = None


class IngestResult(Strict):
    filename: str
    size_bytes: int
    kind: KIND
    kind_label: str
    items_read: int
    items_unreadable: int
    truncated: bool
    truncated_reason: Optional[str] = None
    duration_ms: int
    severity: SEVERITY
    composite_score: float
    time_first: Optional[float] = None
    time_last: Optional[float] = None
    sensors: list[SensorStat] = Field(max_length=10)
    sources: list[SourceSummary] = Field(max_length=20)
    findings: list[Finding] = Field(max_length=50)
    breakdown: dict[str, int] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list, max_length=12)
