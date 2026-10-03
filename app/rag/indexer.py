import time

from pinecone import Pinecone
from pinecone.exceptions import PineconeException

from app.core.config import get_settings
from app.core.logging import get_logger
from app.rag.chunk import Chunk

UPSERT_BATCH_SIZE = 100
DELETE_BATCH_SIZE = 1000
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 3.0
EXPECTED_METRIC = "cosine"
ID_HASH_CHARS = 8


logger = get_logger("rag.indexer")


class IndexerError(Exception):
    pass


def vector_id(chunk: Chunk) -> str:
    short_hash = chunk.content_hash[:ID_HASH_CHARS]

    return f"{chunk.doc_id}:{chunk.chunk_index}:{short_hash}"


def build_metadata(chunk: Chunk) -> dict[str, str | int]:
    return {
        "doc_id": chunk.doc_id,
        "book_title": chunk.book_title,
        "chapter": chunk.chapter,
        "year": chunk.year,
        "page_start": chunk.page_start,
        "page_end": chunk.page_end,
        "chunk_index": chunk.chunk_index,
        "content_type": chunk.content_type,
        "text": chunk.text,
    }


def build_records(
    chunks: list[Chunk], vectors: list[list[float]]
) -> list[dict]:
    records = []

    for chunk, vector in zip(chunks, vectors):
        records.append(
            {
                "id": vector_id(chunk),
                "values": vector,
                "metadata": build_metadata(chunk),
            }
        )

    return records


def open_index():
    settings = get_settings()

    if settings.pinecone_api_key is None:
        raise IndexerError("PINECONE_API_KEY is not configured")

    client = Pinecone(api_key=settings.pinecone_api_key.get_secret_value())

    try:
        description = client.describe_index(settings.pinecone_index_name)
    except PineconeException as exc:
        logger.warning("describe_index failed: %s", type(exc).__name__)
        raise IndexerError("could not describe the pinecone index") from None

    # Fail closed: never write vectors into an index of the wrong shape.
    if description.dimension != settings.embedding_dimension:
        raise IndexerError("index dimension does not match the settings")

    if description.metric != EXPECTED_METRIC:
        raise IndexerError("index metric is not cosine")

    host = settings.pinecone_index_host or description.host

    if settings.pinecone_index_host and description.host != host:
        raise IndexerError("PINECONE_INDEX_HOST does not match the index")

    return client.Index(host=host)


def retry_call(action, *args, **kwargs):
    for attempt in range(MAX_ATTEMPTS):
        try:
            return action(*args, **kwargs)
        except PineconeException as exc:
            if attempt == MAX_ATTEMPTS - 1:
                logger.warning("pinecone call failed: %s", type(exc).__name__)
                raise IndexerError("pinecone call failed") from None

            time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))


def upsert_records(index, namespace: str, records: list[dict]) -> int:
    for start in range(0, len(records), UPSERT_BATCH_SIZE):
        batch = records[start:start + UPSERT_BATCH_SIZE]
        retry_call(index.upsert, vectors=batch, namespace=namespace)

    return len(records)


def listed_ids(index, namespace: str, doc_id: str) -> list[str]:
    ids = []

    for page in index.list(prefix=f"{doc_id}:", namespace=namespace):
        for item in page.vectors or []:
            ids.append(item.id)

    return ids


def delete_stale(
    index, namespace: str, doc_id: str, keep_ids: set[str]
) -> int:
    # Runs after the upsert, so a book is never left without its vectors.
    current = listed_ids(index, namespace, doc_id)
    stale = [vector for vector in current if vector not in keep_ids]

    for start in range(0, len(stale), DELETE_BATCH_SIZE):
        batch = stale[start:start + DELETE_BATCH_SIZE]
        retry_call(index.delete, ids=batch, namespace=namespace)

    return len(stale)
