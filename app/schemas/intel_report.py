
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class IndicatorFacts(BaseModel):
    value: str = Field(max_length=256)
    kind: Literal["ip", "domain", "url", "file_hash"]
    abuseipdb_score: int | None = Field(default=None, ge=0, le=100)
    abuseipdb_reports: int | None = Field(default=None, ge=0)
    virustotal_malicious: int | None = Field(default=None, ge=0)
    virustotal_engines: int | None = Field(default=None, ge=0)
    shodan_ports: list[int] = Field(default_factory=list, max_length=64)
    shodan_tags: list[str] = Field(default_factory=list, max_length=16)
    country: str | None = Field(default=None, max_length=2)
    asn_org: str | None = Field(default=None, max_length=128)
    greynoise_class: Literal["benign", "malicious", "unknown"] | None = None
    greynoise_noise: bool | None = None
    failed_sources: list[str] = Field(default_factory=list, max_length=8)


class IntelAssessment(BaseModel):
    reputation: Literal["clean", "suspicious", "malicious", "unknown"]
    scope: Literal["mass_scanner", "targeted", "unclear"]
    severity_adjustment: Literal["lower", "keep", "raise"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=500)
    notes: str = Field(default="", max_length=800)


class IntelReport(BaseModel):
    case_key: str
    generated_at: datetime
    facts: list[IndicatorFacts] = Field(max_length=10)
    assessment: IntelAssessment
    