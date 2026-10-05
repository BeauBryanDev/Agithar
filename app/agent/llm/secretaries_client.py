from openai import AsyncOpenAI

from app.core.config import get_settings

REQUEST_TIMEOUT_SECONDS = 90.0
MAX_RETRIES = 2


class SecretaryConfigError(Exception):
    pass


_client: AsyncOpenAI | None = None


def get_openai_client() -> AsyncOpenAI:
    global _client

    if _client is None:
        key = get_settings().openai_api_key

        if key is None:
            raise SecretaryConfigError("openai api key is not configured")

        _client = AsyncOpenAI(
            api_key=key.get_secret_value(),
            timeout=REQUEST_TIMEOUT_SECONDS,
            max_retries=MAX_RETRIES,
        )

    return _client


async def generate_secretary_report(
    system_prompt: str, user_content: str
) -> str:
    settings = get_settings()
    client = get_openai_client()

    response = await client.responses.create(
        model=settings.secretary_model,
        instructions=system_prompt,
        input=user_content,
        reasoning={"effort": settings.secretary_effort},
        max_output_tokens=settings.secretary_max_output_tokens,
        store=False,
    )

    # An incomplete response (the cap was reached) has no usable draft.
    if response.status != "completed":
        return ""

    return response.output_text
