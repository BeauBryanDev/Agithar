from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class TimelinePoint(BaseModel):
    timestamp: datetime
    # Highest composite score of the incidents in the bucket, 0 if none.
    score: float = Field(ge=0.0, le=1.0)
    incidents: int = Field(ge=0)

    model_config = ConfigDict(extra="forbid")


class SensorCount(BaseModel):
    sensor: str = Field(max_length=64)
    count: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class TechniqueCount(BaseModel):
    technique: str = Field(max_length=16)
    name: Optional[str] = Field(default=None, max_length=200)
    count: int = Field(ge=1)

    model_config = ConfigDict(extra="forbid")


class DashboardData(BaseModel):
    window_hours: int = Field(ge=1)
    total_incidents: int = Field(ge=0)
    # True when the window holds more incidents than were read.
    truncated: bool = False
    severity_distribution: dict[str, int]
    status_counts: dict[str, int]
    # Mean confidence of the master's verdicts, None when there are none.
    avg_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    timeline: list[TimelinePoint]
    by_sensor: list[SensorCount]
    top_techniques: list[TechniqueCount]

    model_config = ConfigDict(extra="forbid")
