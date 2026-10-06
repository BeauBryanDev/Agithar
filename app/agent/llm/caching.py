from typing import Any

from langchain_core.messages import SystemMessage

from app.core.config import get_settings

CACHE = {"type": "ephemeral"}


def cached_system(prompt: str) -> SystemMessage:
    if not get_settings().agent_prompt_cache:
        return SystemMessage(prompt)

    # The breakpoint on the last system block caches the tool definitions
    # (which come first in the request) together with the system prompt.
    block = {"type": "text", "text": prompt, "cache_control": CACHE}

    return SystemMessage(content=[block])


def with_cache(model: Any) -> Any:
    # Automatic caching of the growing conversation, on top of the system
    # breakpoint: each later turn reads the earlier turns.
    if not get_settings().agent_prompt_cache:
        return model

    return model.bind(cache_control=CACHE)
