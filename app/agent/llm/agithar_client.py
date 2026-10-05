from langchain_anthropic import ChatAnthropic

from app.core.config import get_settings


class AgentConfigError(Exception):
    pass


_client: ChatAnthropic | None = None


def get_anthropic_client() -> ChatAnthropic:
    global _client

    if _client is None:
        settings = get_settings()

        if settings.anthropic_api_key is None:
            raise AgentConfigError("anthropic api key is not configured")

        # No temperature, top_p or top_k: this model rejects them.
        _client = ChatAnthropic(
            model=settings.agent_model,
            api_key=settings.anthropic_api_key.get_secret_value(),
            max_tokens=settings.agent_max_tokens,
            output_config={"effort": settings.agent_effort},
        )

    return _client
