
from langchain_anthropic import ChatAnthropic

from app.core.config import get_settings

ANALYST_MODEL = "claude-haiku-5-5"
ANALYST_MAX_TOKENS = 4096
ANALYST_EFFORT = "medium"


class AnalystConfigError(Exception):
    pass


_client: ChatAnthropic | None = None


def get_analyst_client() -> ChatAnthropic:
    global _client

    if _client is None:
        settings = get_settings()

        if settings.anthropic_api_key is None:
            raise AnalystConfigError("anthropic api key is not configured")

        # No temperature, top_p or top_k: this model rejects them.
        # No fallback beta: server-side fallback is not offered on this model.
        _client = ChatAnthropic(
            model=ANALYST_MODEL,
            api_key=settings.anthropic_api_key.get_secret_value(),
            max_tokens=ANALYST_MAX_TOKENS,
            output_config={"effort": ANALYST_EFFORT},
        )

    return _client
