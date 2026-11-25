
import  ipaddress
from datetime import datetime
from typing import Literal, Self 

from pydantic import BaseModel, Field , model_validator


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


class IndicatorInput(BaseModel):
    value: str = Field(min_length=1, max_length=256)
    kind: Literal["ip", "domain", "url", "file_hash"]

    @model_validator(mode="after")
    def ip_must_be_public(self) -> Self:
        # Private or reserved addresses never leave the server.
        if self.kind == "ip" and not ipaddress.ip_address(self.value).is_global:
            raise ValueError("ip must be a public address")
        return self
        

class IntelAssessment(BaseModel):
    reputation: Literal["clean", "suspicious", "malicious", "unknown"]
    scope: Literal["mass_scanner", "targeted", "unclear"]
    severity_adjustment: Literal["lower", "keep", "raise"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(max_length=500)
    notes: str = Field(default="", max_length=800)


class IntelReport(BaseModel):
    case_key: str | None = None 
    generated_at: datetime
    facts: list[IndicatorFacts] = Field(max_length=10)
    assessment: IntelAssessment
    