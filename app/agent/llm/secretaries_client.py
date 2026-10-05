
from openai import OpenAI

from app.core.config import get_settings

MODEL = "gpt-6-luna"
REASONING_EFFORT = "medium"
MAX_OUTPUT_TOKENS = 2048

_client: OpenAI | None = None


def get_openai_client() -> OpenAI:
    global _client

    if _client is None:
        settings = get_settings()
        _client = OpenAI(api_key=settings.openai_api_key.get_secret_value())

    return _client


def generate_secretary_report(system_prompt: str, user_content: str) -> str:
    client = get_openai_client()

    response = client.responses.create(
        model=MODEL,
        reasoning={"effort": REASONING_EFFORT},
        max_output_tokens=MAX_OUTPUT_TOKENS,
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    )

    return response.output_text
