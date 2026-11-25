
import ipaddress
from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, Field, field_validator, model_validator


class ListeningPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    proto: Literal["tcp", "udp"]
    process: str | None = Field(default=None, max_length=64)
    public: bool


class FirewallState(BaseModel):
    active: bool
    default_incoming: Literal["allow", "deny", "reject", "unknown"]
    rule_count: int = Field(ge=0)
    listening: list[ListeningPort] = Field(max_length=64)


class SigmaMatch(BaseModel):
    rule_id: str = Field(max_length=64)
    title: str = Field(max_length=160)
    level: Literal["low", "medium", "high", "critical"]
    count: int = Field(ge=1)


class NetworkFinding(BaseModel):
    category: Literal[
        "posture_drift", "rule_gap", "suspicious_traffic",
        "firewall_blocks", "sigma_match",
    ]
    severity: Literal["low", "medium", "high"]
    description: str = Field(max_length=300)
    evidence: list[str] = Field(default_factory=list, max_length=5)


class ProposedAction(BaseModel):
    action: Literal["deny_ip", "limit_port", "close_port"]
    ip: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    proto: Literal["tcp", "udp"] | None = None
    rationale: str = Field(max_length=300)
    risk: Literal["low", "medium", "high"]

    @field_validator("ip")
    @classmethod
    def ip_must_be_global(cls, value: str | None) -> str | None:
        if value is not None and not ipaddress.ip_address(value).is_global:
            raise ValueError("ip must be a public address")
        return value

    @model_validator(mode="after")
    def required_fields_per_action(self) -> Self:
        if self.action == "deny_ip" and self.ip is None:
            raise ValueError("deny_ip requires ip")
        if self.action in ("limit_port", "close_port") and (
            self.port is None or self.proto is None
        ):
            raise ValueError("port actions require port and proto")
        return self


class NetworkAssessment(BaseModel):
    findings: list[NetworkFinding] = Field(max_length=10)
    proposed_actions: list[ProposedAction] = Field(default_factory=list, max_length=5)
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=500)
    notes: str = Field(default="", max_length=800)


class NetworkReport(BaseModel):
    case_key: str | None = None
    mode: Literal["incident", "proactive"]
    generated_at: datetime
    source_generated_at: datetime
    firewall: FirewallState
    sigma: list[SigmaMatch] = Field(default_factory=list, max_length=20)
    assessment: NetworkAssessment
    