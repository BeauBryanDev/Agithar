from datetime import datetime
from typing import Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from app.schemas.analysis import (
    MAX_EVIDENCE_ITEMS,
    MAX_EVIDENCE_REFS,
    MAX_INPUT_CHARS,
    MAX_TEXT_CHARS,
    SESSION_ID_PATTERN,
    DetectorResult,
    EvidenceRef,
)
from app.security.sanitize import sanitize_string

MAX_MESSAGES = 200
MAX_TITLE_CHARS = 120
MESSAGE_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"

MESSAGE_ROLE = Literal["analyst", "system"]
STREAM_EVENT = Literal["token", "evidence", "done", "error", "status"]


class ChatMessage(BaseModel):
    id: str = Field(pattern=MESSAGE_ID_PATTERN)
    role: MESSAGE_ROLE
    content: str = Field(max_length=MAX_TEXT_CHARS + 32)
    evidence_refs: list[EvidenceRef] = Field(
        default_factory=list, max_length=MAX_EVIDENCE_REFS
    )
    streaming: bool = False
    created_at: datetime

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, value: str) -> str:
        return sanitize_string(str(value), MAX_TEXT_CHARS, keep_newlines=True)

    @model_validator(mode="after")
    def check_spans(self) -> "ChatMessage":
        for ref in self.evidence_refs:
            if ref.claim_span[1] > len(self.content):
                raise ValueError("claim_span is outside the content")

        return self


class ChatRequest(BaseModel):
    input: str = Field(min_length=1, max_length=MAX_INPUT_CHARS)
    session_id: Optional[str] = Field(
        default=None, pattern=SESSION_ID_PATTERN
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("input")
    @classmethod
    def sanitize_input(cls, value: str) -> str:
        return sanitize_string(value, MAX_INPUT_CHARS, keep_newlines=True)


class ChatSessionSummary(BaseModel):
    id: str = Field(pattern=SESSION_ID_PATTERN)
    title: str = Field(max_length=MAX_TITLE_CHARS + 32)
    created_at: datetime

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, value: str) -> str:
        return sanitize_string(str(value), MAX_TITLE_CHARS)


class ChatSession(ChatSessionSummary):
    messages: list[ChatMessage] = Field(
        default_factory=list, max_length=MAX_MESSAGES
    )
    evidence: list[DetectorResult] = Field(
        default_factory=list, max_length=MAX_EVIDENCE_ITEMS
    )

    @model_validator(mode="after")
    def check_refs(self) -> "ChatSession":
        known = {item.id for item in self.evidence}

        for message in self.messages:
            for ref in message.evidence_refs:
                if ref.id not in known:
                    raise ValueError("evidence_ref points to unknown evidence")

        return self


class ChatSessionList(BaseModel):
    items: list[ChatSessionSummary]
    total: int = Field(ge=0)
    skip: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)


class ChatReply(BaseModel):
    session_id: str = Field(pattern=SESSION_ID_PATTERN)
    message: ChatMessage
    evidence: list[DetectorResult] = Field(
        default_factory=list, max_length=MAX_EVIDENCE_ITEMS
    )

    model_config = ConfigDict(extra="forbid")


class ChatStreamEvent(BaseModel):
    type: STREAM_EVENT
    text: Optional[str] = Field(default=None, max_length=MAX_TEXT_CHARS + 32)
    evidence: Optional[list[DetectorResult]] = Field(
        default=None, max_length=MAX_EVIDENCE_ITEMS
    )
    reply: Optional[ChatReply] = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("text", mode="before")
    @classmethod
    def sanitize_text(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        return sanitize_string(str(value), MAX_TEXT_CHARS, keep_newlines=True)
