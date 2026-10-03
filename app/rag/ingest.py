from dataclasses import dataclass

from app.core.logging import get_logger
from app.rag.chunk import Chunk, chunk_book
from app.rag.clean import clean_book
from app.rag.embed import embed_chunks
from app.rag.extract import extract_book
from app.rag.indexer import (
    build_records,
    delete_stale,
    open_index,
    upsert_records,
)
from app.rag.manifest import Book

logger = get_logger("rag.ingest")


@dataclass
class IngestResult:
    doc_id: str
    namespace: str
    chunks: int
    tokens: int
    cached: int = 0
    embedded: int = 0
    upserted: int = 0
    deleted: int = 0


def prepare_chunks(book: Book) -> list[Chunk]:
    pages = extract_book(book)

    return chunk_book(clean_book(pages, book), book)


def plan_book(book: Book) -> IngestResult:
    chunks = prepare_chunks(book)

    return IngestResult(
        doc_id=book.doc_id,
        namespace=book.namespace,
        chunks=len(chunks),
        tokens=sum(chunk.token_count for chunk in chunks),
    )


def ingest_book(book: Book, index) -> IngestResult:
    chunks = prepare_chunks(book)
    vectors, stats = embed_chunks(chunks)
    records = build_records(chunks, vectors)

    upserted = upsert_records(index, book.namespace, records)
    keep = {record["id"] for record in records}
    deleted = delete_stale(index, book.namespace, book.doc_id, keep)

    logger.info(
        "book ingested",
        extra={"doc_id": book.doc_id, "upserted": upserted},
    )

    return IngestResult(
        doc_id=book.doc_id,
        namespace=book.namespace,
        chunks=len(chunks),
        tokens=sum(chunk.token_count for chunk in chunks),
        cached=stats.cached,
        embedded=stats.requested,
        upserted=upserted,
        deleted=deleted,
    )


def ingest_books(books: list[Book]) -> list[IngestResult]:
    index = open_index()

    return [ingest_book(book, index) for book in books]
