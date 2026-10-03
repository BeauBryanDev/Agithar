import hashlib
from dataclasses import dataclass

from app.core.logging import get_logger
from app.rag.clean import CleanPage
from app.rag.manifest import Book
from app.rag.pieces import CHUNK_TOKENS, Piece, section_pieces
from app.rag.tokens import count_tokens

OVERLAP_TOKENS = 112
MIN_NEW_TOKENS = 64
MERGE_SLACK_TOKENS = 64
JOIN_COST_TOKENS = 1


logger = get_logger("rag.chunk")


@dataclass(frozen=True)
class Chunk:
    doc_id: str
    namespace: str
    book_title: str
    chapter: str
    year: int
    page_start: int
    page_end: int
    chunk_index: int
    text: str
    token_count: int
    content_type: str
    content_hash: str


@dataclass
class Group:
    pieces: list[Piece]
    new_start: int


def total_tokens(pieces: list[Piece]) -> int:
    return sum(piece.tokens + JOIN_COST_TOKENS for piece in pieces)


def overlap_tail(pieces: list[Piece]) -> list[Piece]:
    # The overlap is made of whole sentences and never reaches a listing.
    tail: list[Piece] = []
    used = 0

    for piece in reversed(pieces):
        cost = piece.tokens + JOIN_COST_TOKENS

        if piece.atomic or used + cost > OVERLAP_TOKENS:
            break

        tail.insert(0, piece)
        used += cost

    return tail


def assemble(pieces: list[Piece]) -> list[Group]:
    groups: list[Group] = []
    current: list[Piece] = []
    new_start = 0

    for piece in pieces:
        cost = piece.tokens + JOIN_COST_TOKENS

        if current and total_tokens(current) + cost > CHUNK_TOKENS:
            groups.append(Group(current, new_start))
            current = overlap_tail(current)

            if current and total_tokens(current) + cost > CHUNK_TOKENS:
                current = []

            new_start = len(current)

        current.append(piece)

    if current:
        groups.append(Group(current, new_start))

    return merge_small_tail(groups)


def merge_small_tail(groups: list[Group]) -> list[Group]:
    # A last chunk with almost no new content joins the previous chunk.
    if len(groups) < 2:
        return groups

    last = groups[-1]
    fresh = last.pieces[last.new_start:]

    if total_tokens(fresh) >= MIN_NEW_TOKENS:
        return groups

    previous = groups[-2]
    limit = CHUNK_TOKENS + MERGE_SLACK_TOKENS

    if total_tokens(previous.pieces) + total_tokens(fresh) > limit:
        return groups

    previous.pieces.extend(fresh)

    return groups[:-1]


def render(pieces: list[Piece]) -> str:
    parts = []

    for index, piece in enumerate(pieces):
        parts.append(piece.text if index == 0 else piece.joiner + piece.text)

    return "".join(parts)


def content_type(pieces: list[Piece]) -> str:
    kinds = {piece.kind for piece in pieces}

    return kinds.pop() if len(kinds) == 1 else "mixed"


def build_chunk(group: Group, 
                book: Book, 
                chapter: str, 
                index: int
                ) -> Chunk:
    text = render(group.pieces)

    return Chunk(
        doc_id=book.doc_id,
        namespace=book.namespace,
        book_title=book.title,
        chapter=chapter,
        year=book.year,
        page_start=min(piece.page_start for piece in group.pieces),
        page_end=max(piece.page_end for piece in group.pieces),
        chunk_index=index,
        text=text,
        token_count=count_tokens(text),
        content_type=content_type(group.pieces),
        content_hash=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )


def sections_in_order(pages: list[CleanPage]) -> list[list[CleanPage]]:
    sections: list[list[CleanPage]] = []

    for page in pages:
        if sections and sections[-1][0].section_title == page.section_title:
            sections[-1].append(page)
        else:
            sections.append([page])

    return sections


def chunk_book(pages: list[CleanPage], 
               book: Book
               ) -> list[Chunk]:
    chunks: list[Chunk] = []

    for section_pages in sections_in_order(pages):
        chapter = section_pages[0].section_title
        groups = assemble(section_pieces(section_pages))

        for group in groups:
            chunks.append(build_chunk(group, 
                                      book, 
                                      chapter, 
                                      len(chunks))
                          )

    logger.info(
        "book chunked",
        extra={"doc_id": book.doc_id, "chunks": len(chunks)},
    )

    return chunks
