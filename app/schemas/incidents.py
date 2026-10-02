
from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

SEVERITY = Literal["low", "medium", "high"]
# TODO: confirm whether this should mirror AutomatonState.verdict from automaton state
STATUS = Literal["open", "confirmed", "false_positive", "needs_human", "closed"]
# verdict: "confirmed" | "false_positive" | "needs_human"
# reported_md: str | None
# notified: bool
# this status should reflects same values from veredict + close state 
# open → confirmed/false_positive/needs_human → closed
IOC_TYPE = Literal["ip", "user_agent", "hash", "url"]


class IOCRead(BaseModel):
    ioc_id: int
    ioc_type: IOC_TYPE
    value: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ActionTakenRead(BaseModel):
    action_id: int
    tool_name: str
    params: Optional[dict[str, Any]] = None
    result: Optional[dict[str, Any]] = None
    performed_by: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentSummary(BaseModel):
    incident_id: int
    case_key: str
    ip: str
    severity: SEVERITY
    composite_score: float
    status: STATUS
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    def __repr__(self) -> str:
        return f"IncidentSummary(case_key={self.case_key!r}, severity={self.severity!r})"


class IncidentRead(IncidentSummary):
    num_sensors: int
    num_strong_sensors: int
    contributing_sensors: list[str]
    sensor_scores: dict[str, float]
    event_counts: dict[str, int]
    evidence: list[dict[str, Any]]
    updated_at: datetime
    iocs: list[IOCRead] = Field(default_factory=list)
    actions: list[ActionTakenRead] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)

    def __repr__(self) -> str:
        return f"IncidentRead(case_key={self.case_key!r})"


class IncidentList(BaseModel):
    items: list[IncidentSummary]
    total: int = Field(ge=0)
    skip: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)


class IncidentStatusUpdate(BaseModel):
    status: STATUS

    model_config = ConfigDict(extra="forbid")
    