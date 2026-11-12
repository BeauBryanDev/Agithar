from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SampleRule(Strict):
    rule_id: str
    title: str


class CoverageRow(Strict):
    technique: str
    name: str
    tactics: list[str]
    parent: Optional[str]
    level: int = Field(ge=0, le=3)
    rules: int
    usable_rules: int
    usable_logs: list[str]
    missing_logs: list[str]
    sensors: list[str]
    offline_sensors: list[str]
    incidents: int
    threat_groups: int
    sample_rules: list[SampleRule]


class LevelCount(Strict):
    level: int
    meaning: str
    techniques: int


class CoverageSummary(Strict):
    techniques_in_scope: int
    levels: list[LevelCount]
    seen_in_incidents: int


class CoverageResponse(Strict):
    summary: CoverageSummary
    collected_logs: list[str]
    incident_window_days: int
    incidents_available: bool
    attack_version: str
    sigma_commit: str
    attribution: list[str]
    rows: list[CoverageRow]
