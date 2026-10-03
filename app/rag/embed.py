import hashlib
import json
import random
import time
from dataclasses import dataclass
from pathlib import Path

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    OpenAI,
    OpenAIError,
    RateLimitError,
)

from app.core.config import PROJECT_ROOT, get_settings
from app.core.logging import get_logger
from app.rag.chunk import Chunk

CACHE_PATH = PROJECT_ROOT / "data" / "rag" / "embedding_cache.jsonl"
BATCH_SIZE = 100
MAX_ATTEMPTS = 5
BASE_DELAY_SECONDS = 2.0
MAX_DELAY_SECONDS = 60.0
REQUEST_TIMEOUT_SECONDS = 60.0
SERVER_ERROR_FLOOR = 500


logger = get_logger("rag.embed")


class EmbedError(Exception):
    pass


@dataclass
class EmbedStats:
    cached: int = 0
    requested: int = 0
    tokens: int = 0


def embed_text(chunk: Chunk) -> str:
    # The book and chapter give the vector the context a bare chunk lacks.
    return f"{chunk.book_title} | {chunk.chapter}\n\n{chunk.text}"


def cache_key(model: str, dimension: int, text: str) -> str:
    raw = f"{model}:{dimension}:{text}".encode("utf-8")

    return hashlib.sha256(raw).hexdigest()


def load_cache(path: Path, dimension: int) -> dict[str, list[float]]:
    cache: dict[str, list[float]] = {}

    if not path.is_file():
        return cache

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
                key, vector = entry["k"], entry["v"]
            except (ValueError, KeyError, TypeError):
                continue

            if isinstance(vector, list) and len(vector) == dimension:
                cache[key] = vector

    return cache


def append_cache(path: Path, entries: dict[str, list[float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as handle:
        for key, vector in entries.items():
            handle.write(json.dumps({"k": key, "v": vector}) + "\n")


def is_retryable(exc: OpenAIError) -> bool:
    if isinstance(exc, (RateLimitError, APIConnectionError, APITimeoutError)):
        return True

    return (
        isinstance(exc, APIStatusError)
        and exc.status_code >= SERVER_ERROR_FLOOR
    )


def request_batch(
    client: OpenAI, model: str, dimension: int, texts: list[str]
) -> tuple[list[list[float]], int]:
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = client.embeddings.create(
                model=model,
                input=texts,
                dimensions=dimension,
                encoding_format="float",
            )
        except OpenAIError as exc:
            if not is_retryable(exc) or attempt == MAX_ATTEMPTS - 1:
                logger.warning(
                    "embedding request failed: %s", type(exc).__name__
                )
                raise EmbedError("embedding request failed") from None

            delay = min(BASE_DELAY_SECONDS * 2**attempt, MAX_DELAY_SECONDS)
            time.sleep(delay + random.uniform(0, 1))
            continue

        vectors = [item.embedding for item in response.data]

        if len(vectors) != len(texts):
            raise EmbedError("embedding count does not match the request")

        return vectors, response.usage.total_tokens

    raise EmbedError("embedding request failed")


def make_client() -> OpenAI:
    key = get_settings().openai_api_key

    if key is None:
        raise EmbedError("OPENAI_API_KEY is not configured")

    return OpenAI(
        api_key=key.get_secret_value(),
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=0,
    )


def embed_chunks(chunks: list[Chunk]) -> tuple[list[list[float]], EmbedStats]:
    settings = get_settings()
    model = settings.embedding_model
    dimension = settings.embedding_dimension
    cache = load_cache(CACHE_PATH, dimension)
    stats = EmbedStats()

    texts = [embed_text(chunk) for chunk in chunks]
    keys = [cache_key(model, dimension, text) for text in texts]
    missing = [i for i, key in enumerate(keys) if key not in cache]
    stats.cached = len(chunks) - len(missing)

    if missing:
        client = make_client()

        for start in range(0, len(missing), BATCH_SIZE):
            batch = missing[start:start + BATCH_SIZE]
            vectors, tokens = request_batch(
                client, model, dimension, [texts[i] for i in batch]
            )
            fresh = {keys[i]: vector for i, vector in zip(batch, vectors)}
            cache.update(fresh)
            append_cache(CACHE_PATH, fresh)
            stats.requested += len(batch)
            stats.tokens += tokens

    logger.info(
        "chunks embedded",
        extra={"cached": stats.cached, "requested": stats.requested},
    )

    return [cache[key] for key in keys], stats


def embed_query(text: str) -> list[float]:
    settings = get_settings()
    client = make_client()
    vectors, _ = request_batch(
        client,
        settings.embedding_model,
        settings.embedding_dimension,
        [text],
    )

    return vectors[0]
