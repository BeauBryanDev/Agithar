from typing import Any, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.security.sanitize import sanitize_detail, sanitize_string

MAX_INPUT_CHARS = 8000
MAX_TEXT_CHARS = 16000
MAX_SUMMARY_CHARS = 2000
MAX_EVIDENCE_ITEMS = 50
MAX_EVIDENCE_REFS = 100
MAX_ID_CHARS = 64
MITRE_PATTERN = r"^T\d{4}(\.\d{3})?$"
OWASP_PATTERN = r"^A\d{2}:2025$"
SESSION_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"

VERDICT = Literal["confirmed", "false_positive", "needs_human"]
DETECTOR_VERDICT = Literal["anomaly", "normal"]


class AgentVerdict(BaseModel):
    verdict: VERDICT
    needs_human: bool
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_technique: Optional[str] = Field(
        default=None, pattern=MITRE_PATTERN
    )
    owasp_category: Optional[str] = Field(
        default=None, pattern=OWASP_PATTERN
    )
    summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS + 32)

    model_config = ConfigDict(extra="forbid")

    @field_validator("summary", mode="before")
    @classmethod
    def sanitize_summary(cls, value: str) -> str:
        return sanitize_string(str(value), MAX_SUMMARY_CHARS)

    @model_validator(mode="after")
    def check_consistency(self) -> "AgentVerdict":
        if self.needs_human != (self.verdict == "needs_human"):
            raise ValueError("needs_human must match verdict")

        return self


class AnalyzeRequest(BaseModel):
    input: str = Field(min_length=1, max_length=MAX_INPUT_CHARS)
    session_id: Optional[str] = Field(
        default=None, pattern=SESSION_ID_PATTERN
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("input")
    @classmethod
    def sanitize_input(cls, value: str) -> str:
        return sanitize_string(value, MAX_INPUT_CHARS)


class DetectorResult(BaseModel):
    id: str = Field(min_length=1, max_length=MAX_ID_CHARS)
    detector: str = Field(min_length=1, max_length=MAX_ID_CHARS)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    verdict: DETECTOR_VERDICT
    threshold: float = Field(ge=0.0, le=1.0)
    raw: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")

    @field_validator("raw")
    @classmethod
    def sanitize_raw(cls, value: dict[str, Any]) -> dict[str, Any]:
        return sanitize_detail(value)


class EvidenceRef(BaseModel):
    id: str = Field(min_length=1, 
                    max_length=MAX_ID_CHARS)
    claim_span: tuple[int, int]

    model_config = ConfigDict(extra="forbid")

    @field_validator("claim_span")
    @classmethod
    def validate_span(cls, value: tuple[int, int]) -> tuple[int, int]:
        start, end = value

        if start < 0 or end < start:
            raise ValueError("claim_span must be a non-negative range")

        return value


class AnalyzeResponse(BaseModel):
    text: str = Field(max_length=MAX_TEXT_CHARS + 32)
    evidence: list[DetectorResult] = Field(
        default_factory=list, 
        max_length=MAX_EVIDENCE_ITEMS
    )
    evidence_refs: list[EvidenceRef] = Field(
        default_factory=list, 
        max_length=MAX_EVIDENCE_REFS
    )
    verdict: Optional[AgentVerdict] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("text", mode="before")
    @classmethod
    def sanitize_text(cls, value: str) -> str:
        return sanitize_string(str(value), MAX_TEXT_CHARS)

    @model_validator(mode="after")
    def check_refs(self) -> "AnalyzeResponse":
        known = {item.id for item in self.evidence}

        for ref in self.evidence_refs:
            if ref.id not in known:
                raise ValueError("evidence_ref points to unknown evidence")

            if ref.claim_span[1] > len(self.text):
                raise ValueError("claim_span is outside the text")

        return self
