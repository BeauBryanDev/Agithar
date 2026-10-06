from functools import lru_cache
from pathlib import Path

PUBLIC_CHAT_PROMPT_PATH = (
    Path(__file__).resolve().parent / "prompts" / "public_chat_mode.md"
)


@lru_cache(maxsize=1)
def load_public_chat_prompt() -> str:
    # Self-contained: this prompt does NOT include load_base_prompt(), which
    # names the real siblings and carries the guardian identity. A public
    # visitor's system prompt must never see that content, tools or not.
    return PUBLIC_CHAT_PROMPT_PATH.read_text(encoding="utf-8")