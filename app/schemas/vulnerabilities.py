import re
from datetime import date, datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.sanitize import sanitize_string

CVE_ID_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,19}$"
CWE_ID_PATTERN = r"^CWE-[0-9]{1,5}$"
OWASP_ID_PATTERN = r"^A[0-9]{2}$"
CVE_ID_REGEX = re.compile(CVE_ID_PATTERN)
MAX_TITLE_CHARS = 256
MAX_SUMMARY_CHARS = 2048
MAX_URL_CHARS = 512
MAX_REFERENCES = 20
MAX_EXPLOITS = 20
MAX_CWES = 10

CVSS_SEVERITY = Literal["none", "low", "medium", "high", "critical"]
CVSS_VERSION = Literal["2.0", "3.0", "3.1", "4.0"]
LOOKUP_SOURCE = Literal["local", "nvd", "exploit_db", "cache"]


def clean_text(value: str, max_chars: int) -> str:
    return sanitize_string(value, max_chars)


class CVSSScore(BaseModel):
    version: CVSS_VERSION
    base_score: float = Field(ge=0.0, le=10.0)
    severity: CVSS_SEVERITY
    vector: Optional[str] = Field(default=None, max_length=128)

    model_config = ConfigDict(extra="forbid")


class ExploitReference(BaseModel):
    edb_id: int = Field(ge=1)
    title: str = Field(max_length=MAX_TITLE_CHARS)
    exploit_type: Optional[str] = Field(default=None, max_length=32)
    platform: Optional[str] = Field(default=None, max_length=64)
    published: Optional[date] = None
    verified: bool = False
    url: Optional[str] = Field(default=None, max_length=MAX_URL_CHARS)

    model_config = ConfigDict(extra="forbid")

    @field_validator("title", "exploit_type", "platform", mode="before")
    @classmethod
    def sanitize_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        return clean_text(str(value), MAX_TITLE_CHARS)


class VulnerabilityRead(BaseModel):
    cve_id: str = Field(pattern=CVE_ID_PATTERN)
    summary: str = Field(max_length=MAX_SUMMARY_CHARS + 32)
    cvss: Optional[CVSSScore] = None
    cwes: list[str] = Field(default_factory=list, max_length=MAX_CWES)
    owasp_categories: list[str] = Field(
        default_factory=list, max_length=MAX_CWES
    )
    published: Optional[datetime] = None
    modified: Optional[datetime] = None
    references: list[str] = Field(
        default_factory=list, max_length=MAX_REFERENCES
    )
    vendor: Optional[str] = Field(default=None, max_length=120)
    vuln_type: Optional[str] = Field(default=None, max_length=120)
    affected: Optional[str] = Field(default=None, max_length=820)
    exploits: list[ExploitReference] = Field(
        default_factory=list, max_length=MAX_EXPLOITS
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("summary", mode="before")
    @classmethod
    def sanitize_summary(cls, value: str) -> str:
        return clean_text(str(value), MAX_SUMMARY_CHARS)

    @field_validator("vendor", "vuln_type", mode="before")
    @classmethod
    def sanitize_short(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else clean_text(str(value), 120)

    @field_validator("affected", mode="before")
    @classmethod
    def sanitize_affected(cls, value: Optional[str]) -> Optional[str]:
        return None if value is None else clean_text(str(value), 800)

    @field_validator("cwes")
    @classmethod
    def validate_cwes(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.match(CWE_ID_PATTERN, item):
                raise ValueError("invalid CWE id")

        return value

    @field_validator("owasp_categories")
    @classmethod
    def validate_owasp(cls, value: list[str]) -> list[str]:
        for item in value:
            if not re.match(OWASP_ID_PATTERN, item):
                raise ValueError("invalid OWASP category id")

        return value

    @field_validator("references")
    @classmethod
    def validate_references(cls, value: list[str]) -> list[str]:
        for item in value:
            if len(item) > MAX_URL_CHARS or not item.startswith("https://"):
                raise ValueError("references must be https URLs")

        return value


class CVELookupRequest(BaseModel):
    cve_id: str

    model_config = ConfigDict(extra="forbid")

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        cleaned = value.strip().upper()

        if not CVE_ID_REGEX.match(cleaned):
            raise ValueError("cve_id must look like CVE-2021-44228")

        return cleaned


class CVELookupResult(BaseModel):
    found: bool
    source: LOOKUP_SOURCE
    vulnerability: Optional[VulnerabilityRead] = None
    note: Optional[str] = Field(default=None, max_length=400)

    @field_validator("note", mode="before")
    @classmethod
    def sanitize_note(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        return clean_text(str(value), 300)

    model_config = ConfigDict(extra="forbid")
