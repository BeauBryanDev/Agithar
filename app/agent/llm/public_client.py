from functools import lru_cache

from langchain_openai import ChatOpenAI

from app.core.config import get_settings

# The public demo does not use the master model: it runs on the secretaries'
# model gpt-6-luna, so Claude Sonnet stays for the SOC admin and operators.
TIMEOUT_SECONDS = 60
MAX_RETRIES = 2


class PublicChatConfigError(Exception):
    pass


@lru_cache
def get_public_llm() -> ChatOpenAI:
    settings = get_settings()
    key = settings.openai_api_key

    if key is None:
        raise PublicChatConfigError("the public chat model is not configured")

    return ChatOpenAI(
        model=settings.public_chat_model,
        api_key=key.get_secret_value(),
        use_responses_api=True,
        reasoning={"effort": settings.public_chat_effort},
        max_tokens=settings.public_chat_max_output_tokens,
        # Visitor conversations are not kept at the provider. The encrypted
        # reasoning items let a tool loop continue without stored state.
        store=False,
        include=["reasoning.encrypted_content"],
        timeout=TIMEOUT_SECONDS,
        max_retries=MAX_RETRIES,
    )
