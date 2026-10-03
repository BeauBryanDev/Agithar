import math
import re
from collections import Counter
from dataclasses import dataclass

from app.core.logging import get_logger
from app.rag.extract import PageText
from app.rag.listings import Block, split_blocks
from app.rag.manifest import Book
from app.security.sanitize import sanitize_string

MAX_PAGE_CHARS = 60_000
EDGE_LINES = 8
MAX_EDGE_LINE_CHARS = 100
MIN_REPEAT_PAGES = 3
FIXED_LINE_PAGE_RATIO = 0.15
MODAL_POSITION_SHARE = 0.6
SOFT_HYPHEN = "­"
FULL_LINE_RATIO = 0.82
FULL_WIDTH_PERCENTILE = 0.90
MIN_FULL_WIDTH = 40
LIST_ITEM = re.compile(
    r"^\s*(?:[•◦▪●‣–—*-]\s|\d{1,3}[.)]\s|[a-z][.)]\s)"
)
HYPHEN_BREAK = re.compile(r"[A-Za-z]-$")
DIGIT_MASK = "\ue000"
DIGITS = re.compile(r"\d+")
SPACES = re.compile(r"\s+")
TABLE_GAP = re.compile(r" {3,}")


logger = get_logger("rag.clean")


@dataclass(frozen=True)
class CleanPage:
    doc_id: str
    namespace: str
    section_title: str
    page: int
    blocks: tuple[Block, ...]


def normalize_page(text: str) -> str:
    text = text.replace("\r", "").replace(SOFT_HYPHEN + "\n", "-\n")
    text = sanitize_string(text, MAX_PAGE_CHARS, keep_newlines=True)

    return "\n".join(line.rstrip() for line in text.split("\n"))


def line_key(line: str) -> str:
    return SPACES.sub(" ", DIGITS.sub(DIGIT_MASK, line)).strip()


def collapse(line: str) -> str:
    return SPACES.sub(" ", line).strip()


def edge_positions(lines: list[str]) -> dict[int, tuple[str, int]]:
    filled = [index for index, line in enumerate(lines) if line.strip()]
    positions: dict[int, tuple[str, int]] = {}

    for rank, index in enumerate(filled[:EDGE_LINES]):
        positions[index] = ("top", rank)

    for rank, index in enumerate(reversed(filled[-EDGE_LINES:])):
        positions.setdefault(index, ("bottom", rank))

    return positions


def edge_indexes(lines: list[str]) -> set[int]:
    return set(edge_positions(lines))


def page_edge_keys(lines: list[str]) -> dict[str, tuple[str, int]]:
    keys: dict[str, tuple[str, int]] = {}

    for index, position in edge_positions(lines).items():
        if len(collapse(lines[index])) <= MAX_EDGE_LINE_CHARS:
            keys.setdefault(line_key(lines[index]), position)

    return keys


def best_position_count(counts: Counter[tuple[str, int]]) -> int:
    # Two adjacent ranks count together: odd and even pages often put the
    # page number one line apart.
    best = 0

    for (side, rank), count in counts.items():
        best = max(best, count + counts.get((side, rank + 1), 0))

    return best


def repeated_keys(all_lines: list[list[str]]) -> set[str]:
    pages_with_key: Counter[str] = Counter()
    positions: dict[str, Counter[tuple[str, int]]] = {}

    for lines in all_lines:
        for key, position in page_edge_keys(lines).items():
            pages_with_key[key] += 1
            positions.setdefault(key, Counter())[position] += 1

    ratio_floor = math.ceil(FIXED_LINE_PAGE_RATIO * len(all_lines))
    keys = set()

    for key, pages in pages_with_key.items():
        if pages < MIN_REPEAT_PAGES:
            continue

        # A real header holds one position on page after page. Content
        # lines that merely recur land at scattered positions.
        if best_position_count(positions[key]) < MODAL_POSITION_SHARE * pages:
            continue

        # Page-numbered lines repeat with a changing number. Fixed text must
        # be on many pages, so real headings like Summary are kept.
        if DIGIT_MASK in key or pages >= ratio_floor:
            keys.add(key)

    return keys


def remove_edges(
    lines: list[str], keys: set[str], strip_exact: set[str]
) -> list[str]:
    drop = set()

    for index in edge_indexes(lines):
        if line_key(lines[index]) in keys:
            drop.add(index)
        elif collapse(lines[index]) in strip_exact:
            drop.add(index)

    return [line for index, line in enumerate(lines) if index not in drop]


def full_width(lines: list[str]) -> int:
    lengths = sorted(len(line.strip()) for line in lines if line.strip())

    if not lengths:
        return MIN_FULL_WIDTH

    position = int(FULL_WIDTH_PERCENTILE * (len(lengths) - 1))

    return max(lengths[position], MIN_FULL_WIDTH)


def join_lines(current: str, line: str) -> str:
    if HYPHEN_BREAK.search(current) and line[:1].islower():
        return current[:-1] + line

    return current + " " + line


def reflow_prose(text: str, width: int) -> str:
    paragraphs: list[str] = []
    current = ""
    previous_length = 0

    for raw in text.split("\n"):
        line = raw.strip()

        if not line:
            continue

        wrapped = previous_length >= width * FULL_LINE_RATIO
        starts_item = LIST_ITEM.match(line) is not None

        if current and wrapped and not starts_item:
            current = join_lines(current, line)
        else:
            if current:
                paragraphs.append(current)

            current = line

        previous_length = len(line)

    if current:
        paragraphs.append(current)

    return "\n".join(paragraphs)


def table_text(text: str) -> str:
    rows = []

    for line in text.split("\n"):
        if line.strip():
            rows.append(TABLE_GAP.sub(" | ", line.strip()))

    return "\n".join(rows)


def build_blocks(text: str, layout: bool) -> tuple[Block, ...]:
    if layout:
        return (Block("table", table_text(text)),) if text.strip() else ()

    parsed = split_blocks(text)
    prose_lines = []

    for block in parsed:
        if block.kind == "prose":
            prose_lines.extend(block.text.split("\n"))

    width = full_width(prose_lines)
    blocks = []

    for block in parsed:
        if block.kind == "prose":
            blocks.append(Block("prose", reflow_prose(block.text, width)))
        else:
            blocks.append(block)

    return tuple(blocks)


def clean_book(pages: list[PageText], book: Book) -> list[CleanPage]:
    all_lines = [normalize_page(page.text).split("\n") for page in pages]
    keys = repeated_keys(all_lines)
    strip_exact = {collapse(line) for line in book.strip_lines}
    cleaned = []

    for page, lines in zip(pages, all_lines):
        kept = remove_edges(lines, keys, strip_exact)
        blocks = build_blocks("\n".join(kept), page.layout)

        cleaned.append(
            CleanPage(
                doc_id=page.doc_id,
                namespace=page.namespace,
                section_title=page.section_title,
                page=page.page,
                blocks=blocks,
            )
        )

    logger.info(
        "book cleaned",
        extra={"doc_id": book.doc_id, "edge_keys": len(keys)},
    )

    return cleaned
