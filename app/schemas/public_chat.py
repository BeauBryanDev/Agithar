from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.sanitize import sanitize_string

# Hard schema bounds. The visitor message limit that applies is the setting
# `public_chat_message_chars` (640 by default), checked by the router.
MAX_SCHEMA_CHARS = 4000
MAX_HISTORY_MESSAGES = 6
MAX_ASSISTANT_CHARS = 6000
MAX_HISTORY_TOTAL_CHARS = 12000


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GuestToken(Strict):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    role: Literal["guest"] = "guest"

    def __repr__(self) -> str:
        return "GuestToken()"


class HistoryItem(Strict):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, 
                         max_length=MAX_ASSISTANT_CHARS)

    @field_validator("content", mode="after")
    @classmethod
    def clean(cls, value: str) -> str:
        return sanitize_string(value, 
                               MAX_ASSISTANT_CHARS, 
                               keep_newlines=True)


class PublicChatRequest(Strict):
    message: str = Field(min_length=1, 
                         max_length=MAX_SCHEMA_CHARS)
    # The conversation is held by the browser and sent back with each
    # message: the server stores nothing about visitors.
    history: list[HistoryItem] = Field(
        default_factory=list,
        max_length=MAX_HISTORY_MESSAGES
    )

    @field_validator("message", mode="after")
    @classmethod
    def clean(cls, value: str) -> str:
        text = sanitize_string(value,
                               MAX_SCHEMA_CHARS,
                               keep_newlines=True)

        if not text.strip():
            raise ValueError("message is empty")

        return text


class PublicChatReply(Strict):
    reply: str
    # Messages this visitor may still send in the current window.
    remaining: int = Field(ge=0)
