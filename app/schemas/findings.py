import re
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.analysis import AgentVerdict
from app.schemas.incidents import SEVERITY
from app.schemas.vulnerabilities import CVE_ID_PATTERN, CVSS_SEVERITY
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip

MAX_FACTS = 10
MAX_FACT_CHARS = 200
MAX_SOURCES = 20
MAX_CVES = 10
MAX_INDICATORS = 20
MAX_PATH_CHARS = 512
MAX_PORTS = 20
CASE_ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,80}$"
TOOL_NAME_PATTERN = r"^[a-z0-9_]{1,40}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"

# Fixed vocabularies. Nothing here can hold a payload or an exploit step.
# The master picks from these lists; the secretaries only read them.
BLUE_ACTION = Literal[
    "block_ip",
    "rate_limit_ip",
    "monitor_ip",
    "review_logs",
    "review_waf_rules",
    "add_detection_rule",
    "rotate_credentials",
    "patch_software",
    "no_action",
]
RED_ACTION = Literal[
    "patch_software",
    "apply_vendor_mitigation",
    "restrict_exposed_port",
    "disable_unused_service",
    "add_waf_rule",
    "harden_configuration",
    "review_access_controls",
    "enable_monitoring",
    "PortScaning",
]
DETECTION_GAP = Literal[
    "single_sensor_only",
    "low_sensor_confidence",
    "no_flow_data",
    "no_log_sequence",
    "no_http_payload",
]
IMPACT = Literal[
    "data_exposure",
    "service_disruption",
    "account_takeover",
    "code_execution",
    "unknown",
]
COMPONENT = Literal[
    "valtoria_host",
    "agithar",
    "basil",
    "florabelle",
    "colcar",
    "nginx",
]


def unique(values: list) -> list:
    return list(dict.fromkeys(values))


class KeyFact(BaseModel):
    source: str = Field(pattern=TOOL_NAME_PATTERN)
    text: str = Field(min_length=1, max_length=MAX_FACT_CHARS + 32)

    model_config = ConfigDict(extra="forbid")

    @field_validator("text", mode="before")
    @classmethod
    def sanitize_text(cls, value: str) -> str:
        return sanitize_string(str(value), MAX_FACT_CHARS)


class CVEFinding(BaseModel):
    cve_id: str = Field(pattern=CVE_ID_PATTERN)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_severity: Optional[CVSS_SEVERITY] = None
    has_public_exploit: bool = False

    model_config = ConfigDict(extra="forbid")


class IntelSummary(BaseModel):
    abuse_confidence: Optional[int] = Field(default=None, ge=0, le=100)
    vt_malicious: Optional[int] = Field(default=None, ge=0)
    vt_suspicious: Optional[int] = Field(default=None, ge=0)
    country_code: Optional[str] = Field(default=None, pattern=r"^[A-Z]{2}$")

    model_config = ConfigDict(extra="forbid")


class Indicators(BaseModel):
    ip: str
    url_paths: list[str] = Field(default_factory=list,
                                 max_length=MAX_INDICATORS)
    user_agent_hashes: list[str] = Field(default_factory=list,
                                         max_length=MAX_INDICATORS)

    model_config = ConfigDict(extra="forbid")

    @field_validator("ip")
    @classmethod
    def check_ip(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("url_paths", mode="before")
    @classmethod
    def sanitize_paths(cls, values: list[str]) -> list[str]:
        return [sanitize_string(str(v), MAX_PATH_CHARS) for v in values]

    @field_validator("user_agent_hashes")
    @classmethod
    def check_hashes(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.fullmatch(SHA256_PATTERN, value):
                raise ValueError("user agent hash must be sha256 hex")

        return values


class ExposedPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    service: Optional[str] = Field(default=None, max_length=64)

    model_config = ConfigDict(extra="forbid")

    @field_validator("service", mode="before")
    @classmethod
    def sanitize_service(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else sanitize_string(str(value), 64)


class CaseFindings(BaseModel):
    # Built by code from the case and the tool results: case_id, severity,
    # sources_used, key_facts, cves, intel, prior_incidents. The master
    # supplies only the verdict (it already includes MITRE and OWASP).
    case_id: str = Field(pattern=CASE_ID_PATTERN)
    severity: SEVERITY
    verdict: AgentVerdict
    sources_used: list[str] = Field(default_factory=list,
                                    max_length=MAX_SOURCES)
    key_facts: list[KeyFact] = Field(default_factory=list,
                                     max_length=MAX_FACTS)
    cves: list[CVEFinding] = Field(default_factory=list, max_length=MAX_CVES)
    intel: Optional[IntelSummary] = None
    prior_incidents: int = Field(default=0, ge=0)

    model_config = ConfigDict(extra="forbid")

    @field_validator("sources_used")
    @classmethod
    def check_sources(cls, values: list[str]) -> list[str]:
        for value in values:
            if not re.match(TOOL_NAME_PATTERN, value):
                raise ValueError("invalid tool name")

        return unique(values)


class BlueFindings(CaseFindings):
    indicators: Indicators
    # Judgment fields, chosen by the master from the fixed lists.
    recommended_actions: list[BLUE_ACTION] = Field(max_length=9)
    detection_gaps: list[DETECTION_GAP] = Field(default_factory=list,
                                                max_length=5)

    @field_validator("recommended_actions", "detection_gaps")
    @classmethod
    def drop_duplicates(cls, values: list[str]) -> list[str]:
        return unique(values)


class RedFindings(CaseFindings):
    exposed_ports: list[ExposedPort] = Field(default_factory=list,
                                             max_length=MAX_PORTS)
    # Judgment fields, chosen by the master from the fixed lists.
    impact: list[IMPACT] = Field(max_length=5)
    affected_components: list[COMPONENT] = Field(default_factory=list,
                                                 max_length=6)
    recommended_actions: list[RED_ACTION] = Field(max_length=8)

    @field_validator("impact", "affected_components", "recommended_actions")
    @classmethod
    def drop_duplicates(cls, values: list[str]) -> list[str]:
        return unique(values)
