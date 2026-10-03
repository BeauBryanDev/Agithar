import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.logging import get_logger
from app.rag.manifest import Book, Section, resolve_pdf_path
from app.rag.tables import is_table_page

PDFTOTEXT_TIMEOUT_SECONDS = 120
MAX_SECTION_CHARS = 5_000_000
PAGE_SEPARATOR = "\f"


logger = get_logger("rag.extract")


class ExtractError(Exception):
    pass


@dataclass(frozen=True)
class PageText:
    doc_id: str
    namespace: str
    section_title: str
    page: int
    text: str
    layout: bool


def build_command(
    path: Path, first: int, last: int, layout: bool
) -> list[str]:
    command = ["pdftotext", "-f", str(first), "-l", str(last)]
    command += ["-enc", "UTF-8"]

    if layout:
        command.append("-layout")

    command += [str(path), "-"]

    return command


def run_pdftotext(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=PDFTOTEXT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ExtractError("pdftotext could not be run") from None

    if result.returncode != 0:
        raise ExtractError("pdftotext failed")

    text = result.stdout.decode("utf-8", errors="replace")

    if len(text) > MAX_SECTION_CHARS:
        raise ExtractError("pdftotext output is too large")

    return text


def split_pages(text: str, expected: int) -> list[str]:
    # pdftotext ends every page with a form feed, so the last piece is empty.
    pieces = text.split(PAGE_SEPARATOR)

    if pieces and pieces[-1] == "":
        pieces.pop()

    if len(pieces) != expected:
        raise ExtractError(
            f"expected {expected} pages, pdftotext returned {len(pieces)}"
        )

    return pieces


def read_pages(path: Path, section: Section, layout: bool) -> list[str]:
    first = section.pdf_start
    last = section.pdf_end
    command = build_command(path, first, last, layout)

    return split_pages(run_pdftotext(command), last - first + 1)


def choose_pages(
    path: Path, section: Section, mode: str
) -> list[tuple[str, bool]]:
    if mode == "reading":
        return [(text, False) for text in read_pages(path, section, False)]

    layout_pages = read_pages(path, section, True)

    if mode == "layout":
        return [(text, True) for text in layout_pages]

    # Auto: keep the clean reading order unless the page holds a table.
    reading_pages = read_pages(path, section, False)
    chosen = []

    for reading, layout in zip(reading_pages, layout_pages):
        if is_table_page(layout):
            chosen.append((layout, True))
        else:
            chosen.append((reading, False))

    return chosen


def extract_section(
    book: Book, section: Section, path: Path
) -> list[PageText]:
    mode = section.layout or book.layout
    pages = []

    for offset, (text, layout) in enumerate(choose_pages(path, section, mode)):
        pages.append(
            PageText(
                doc_id=book.doc_id,
                namespace=book.namespace,
                section_title=section.title,
                page=section.pdf_start + offset,
                text=text,
                layout=layout,
            )
        )

    return pages


def extract_book(book: Book) -> list[PageText]:
    path = resolve_pdf_path(book)
    pages = []

    for section in book.sections:
        pages.extend(extract_section(book, section, path))

    logger.info(
        "book extracted",
        extra={"doc_id": book.doc_id, "pages": len(pages)},
    )

    return pages
