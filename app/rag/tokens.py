import os
from functools import lru_cache

from app.core.config import PROJECT_ROOT

TIKTOKEN_CACHE_DIR = PROJECT_ROOT / "data" / "rag" / "tiktoken"
ENCODING_NAME = "cl100k_base"


@lru_cache(maxsize=1)
def get_encoder():
    # The vocabulary file is cached inside the project, not in /tmp, so a
    # reboot or an offline server never triggers a download.
    TIKTOKEN_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("TIKTOKEN_CACHE_DIR", str(TIKTOKEN_CACHE_DIR))

    import tiktoken

    return tiktoken.get_encoding(ENCODING_NAME)


def count_tokens(text: str) -> int:
    # Special-token strings in book text must count as plain text.
    return len(get_encoder().encode(text, disallowed_special=()))


def split_by_tokens(text: str, limit: int) -> list[str]:
    encoder = get_encoder()
    tokens = encoder.encode(text, disallowed_special=())
    parts = []

    for start in range(0, len(tokens), limit):
        parts.append(encoder.decode(tokens[start:start + limit]))

    return parts
