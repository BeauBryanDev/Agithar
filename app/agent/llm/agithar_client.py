from langchain_anthropic import ChatAnthropic

from app.core.config import get_settings

# Beta header of the "default" form of server-side fallbacks.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AgentConfigError(Exception):
    pass


_client: ChatAnthropic | None = None


def get_anthropic_client() -> ChatAnthropic:
    global _client

    if _client is None:
        settings = get_settings()

        if settings.anthropic_api_key is None:
            raise AgentConfigError("anthropic api key is not configured")

        extra: dict = {}

        if settings.agent_fallbacks:
            # When a safeguard declines a request, the API retries it on the
            # model Anthropic recommends for that category, in the same call.
            extra = {
                "betas": [FALLBACK_BETA],
                "model_kwargs": {"fallbacks": "default"},
            }

        # No temperature, top_p or top_k: this model rejects them.
        _client = ChatAnthropic(
            model=settings.agent_model,
            api_key=settings.anthropic_api_key.get_secret_value(),
            max_tokens=settings.agent_max_tokens,
            output_config={"effort": settings.agent_effort},
            **extra,
        )

    return _client
