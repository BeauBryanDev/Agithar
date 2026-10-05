
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
    verdict: Optional[dict[str, Any]] = None
    report_md: Optional[str] = None
    notified: bool = False
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
    


class FeedItem(BaseModel):
    # One line of the detection feed: an incident with what the master
    # concluded (if it has), flattened for a table.
    incident_id: int
    case_key: str
    ip: str
    severity: SEVERITY
    composite_score: float
    status: STATUS
    created_at: datetime
    sensors: list[str] = Field(default_factory=list)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    mitre_technique: Optional[str] = None
    notified: bool = False

    @classmethod
    def from_incident(cls, incident: Any) -> "FeedItem":
        raw = incident.verdict
        verdict = raw if isinstance(raw, dict) else {}
        confidence = verdict.get("confidence")

        return cls(
            incident_id=incident.incident_id,
            case_key=incident.case_key,
            ip=incident.ip,
            severity=incident.severity,
            composite_score=incident.composite_score,
            status=incident.status,
            created_at=incident.created_at,
            sensors=list(incident.contributing_sensors or []),
            confidence=confidence if isinstance(confidence, float) else None,
            mitre_technique=verdict.get("mitre_technique"),
            notified=bool(incident.notified),
        )


class FeedList(BaseModel):
    items: list[FeedItem]
    total: int = Field(ge=0)
    skip: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
