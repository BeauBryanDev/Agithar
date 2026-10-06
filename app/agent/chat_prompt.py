from functools import lru_cache
from pathlib import Path

from app.agent.demeanor import load_base_prompt

CHAT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "chat_mode.md"
)


@lru_cache(maxsize=1)
def load_chat_prompt() -> str:
    # The master prompt, then the chat rules. Fixed text only, so it is a
    # stable cacheable prefix; nothing from a conversation goes in here.
    chat = CHAT_PROMPT_PATH.read_text(encoding="utf-8")

    return f"{load_base_prompt()}\n\n{chat}"
