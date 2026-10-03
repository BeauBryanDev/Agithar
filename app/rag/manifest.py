import json
import re
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from app.core.config import PROJECT_ROOT
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string

KNOWLEDGE_DIR = PROJECT_ROOT / "knowledge"
MANIFEST_PATH = KNOWLEDGE_DIR / "manifest.json"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_TITLE_CHARS = 200
MAX_STRIP_LINES = 20
MAX_SECTIONS = 100
PDFINFO_TIMEOUT_SECONDS = 15
DOC_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PAGES_PATTERN = re.compile(r"^Pages:\s+(\d+)\s*$", re.MULTILINE)
NAMESPACES = Literal["soc", "linux-admin", "offensive"]
LAYOUT_MODES = Literal["reading", "layout", "auto"]


logger = get_logger("rag.manifest")


class ManifestError(Exception):
    pass


def clean_title(value: str) -> str:
    return sanitize_string(value, MAX_TITLE_CHARS)


class Section(BaseModel):
    title: str = Field(min_length=1, 
                       max_length=MAX_TITLE_CHARS)
    
    pdf_start: int = Field(ge=1)
    pdf_end: int = Field(ge=1)
    layout: LAYOUT_MODES | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("title must be a string")

        return clean_title(value)

    @model_validator(mode="after")
    def check_page_order(self) -> "Section":
        if self.pdf_end < self.pdf_start:
            raise ValueError("pdf_end is before pdf_start")

        return self


class Book(BaseModel):
    doc_id: str
    title: str = Field(min_length=1, 
                       max_length=MAX_TITLE_CHARS)
    path: str = Field(min_length=1,
                      max_length=512)
    namespace: NAMESPACES
    year: int = Field(ge=1950, le=2100)
    layout: LAYOUT_MODES = "reading"
    version: str | None = Field(default=None,
                                max_length=32)
    strip_lines: list[str] = Field(
        default_factory=list, max_length=MAX_STRIP_LINES
    )
    sections: list[Section] = Field(min_length=1, 
                                    max_length=MAX_SECTIONS)

    model_config = ConfigDict(extra="forbid")

    @field_validator("doc_id")
    @classmethod
    def check_doc_id(cls, value: str) -> str:
        if not DOC_ID_PATTERN.match(value):
            raise ValueError("doc_id must be lowercase letters, digits, -")

        return value

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("title must be a string")

        return clean_title(value)

    @field_validator("strip_lines", mode="before")
    @classmethod
    def sanitize_strip_lines(cls, value: list[str]) -> list[str]:
        if not isinstance(value, list):
            raise ValueError("strip_lines must be a list")

        lines = []

        for line in value:
            if not isinstance(line, str):
                raise ValueError("strip_lines items must be strings")

            cleaned = clean_title(line).strip()

            if cleaned:
                lines.append(cleaned)

        return lines

    @field_validator("path")
    @classmethod
    def check_path_shape(cls, value: str) -> str:
        parts = Path(value).parts

        if Path(value).is_absolute() or ".." in parts:
            raise ValueError("path must be relative with no '..'")

        if not value.lower().endswith(".pdf"):
            raise ValueError("path must point to a .pdf file")

        return value

    @model_validator(mode="after")
    def check_no_overlap(self) -> "Book":
        ordered = sorted(self.sections, key=section_start)
        previous_end = 0

        for section in ordered:
            if section.pdf_start <= previous_end:
                raise ValueError(f"sections overlap near {section.title!r}")

            previous_end = section.pdf_end

        return self


def section_start(section: Section) -> int:
    return section.pdf_start


class Manifest(BaseModel):
    version: Literal[1]
    books: list[Book] = Field(min_length=1)

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def check_unique_doc_ids(self) -> "Manifest":
        seen = set()

        for book in self.books:
            if book.doc_id in seen:
                raise ValueError(f"duplicate doc_id {book.doc_id!r}")

            seen.add(book.doc_id)

        return self


def resolve_pdf_path(book: Book) -> Path:
    # The resolved path must stay inside knowledge/, even through symlinks.
    resolved = (PROJECT_ROOT / book.path).resolve()

    if not resolved.is_relative_to(KNOWLEDGE_DIR.resolve()):
        raise ManifestError(f"{book.doc_id}: path leaves knowledge/")

    if not resolved.is_file():
        raise ManifestError(f"{book.doc_id}: pdf not found at {book.path}")

    return resolved


def pdf_page_count(path: Path) -> int:
    try:
        result = subprocess.run(
            ["pdfinfo", str(path)],
            capture_output=True,
            text=True,
            timeout=PDFINFO_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ManifestError("pdfinfo could not be run") from None

    match = PAGES_PATTERN.search(result.stdout)

    if result.returncode != 0 or match is None:
        raise ManifestError(f"pdfinfo failed for {path.name}")

    return int(match.group(1))


def check_book_files(book: Book) -> None:
    pages = pdf_page_count(resolve_pdf_path(book))
    last = max(section.pdf_end for section in book.sections)

    if last > pages:
        raise ManifestError(
            f"{book.doc_id}: section ends at page {last}, pdf has {pages}"
        )


def first_error(exc: ValidationError) -> str:
    error = exc.errors()[0]
    location = ".".join(str(part) for part in error["loc"])

    return f"{location}: {error['msg']}"


def load_manifest(
    path: Path = MANIFEST_PATH, check_files: bool = True
) -> Manifest:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError("manifest file is too large")

        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        raise ManifestError(f"manifest not readable at {path.name}") from None
    
    except ValueError:
        raise ManifestError("manifest is not valid json") from None

    try:
        manifest = Manifest.model_validate(raw)
    except ValidationError as exc:
        raise ManifestError(f"invalid manifest: {first_error(exc)}") from None

    if check_files:
        for book in manifest.books:
            check_book_files(book)

    logger.info("manifest loaded", extra={"books": len(manifest.books)})

    return manifest
