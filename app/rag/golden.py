import json
from dataclasses import asdict
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.rag.chunk import Chunk
from app.rag.ingest import prepare_chunks
from app.rag.manifest import MANIFEST_PATH, load_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
GOLDEN_PATH = PROJECT_ROOT / "data" / "rag" / "golden_set.jsonl"
EVAL_DIR = PROJECT_ROOT / "data" / "rag" / "eval"
CORPUS_CACHE = EVAL_DIR / "chunks.jsonl"
NAMESPACE = Literal["soc", "linux-admin", "offensive"]
QUESTION_TYPE = Literal[
    "direct", "paraphrase", "keyword", "listing", "multi", "negative"
]
CHUNK_ID_PATTERN = r"^[a-z0-9-]{1,64}:[0-9]{1,5}$"
HASH8_PATTERN = r"^[0-9a-f]{8}$"
MAX_QUESTIONS = 500


class GoldenError(Exception):
    pass


class Label(BaseModel):
    chunk: str = Field(pattern=CHUNK_ID_PATTERN)
    hash8: str = Field(pattern=HASH8_PATTERN)
    grade: Literal[1, 2]

    model_config = ConfigDict(extra="forbid")


class GoldenQuestion(BaseModel):
    id: str = Field(pattern=r"^[a-z]{3,8}-[0-9]{3}$")
    namespace: NAMESPACE
    type: QUESTION_TYPE
    question: str = Field(min_length=5, max_length=500)
    relevant: list[Label] = Field(default_factory=list, max_length=20)
    pages: list[tuple[str, int, int]] = Field(
        default_factory=list, max_length=10
    )
    note: Optional[str] = Field(default=None, max_length=500)

    model_config = ConfigDict(extra="forbid")

    def grades(self) -> dict[str, int]:
        return {label.chunk: label.grade for label in self.relevant}


def chunk_id(doc_id: str, index: int) -> str:
    return f"{doc_id}:{index}"


def check_question(question: GoldenQuestion) -> None:
    if question.type == "negative" and question.relevant:
        raise GoldenError(f"{question.id}: a negative has no labels")

    if question.type != "negative" and not question.relevant:
        raise GoldenError(f"{question.id}: no relevant chunk labelled")


def load_golden(path: Path = GOLDEN_PATH) -> list[GoldenQuestion]:
    questions: list[GoldenQuestion] = []
    seen: set[str] = set()

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        raise GoldenError("golden set file is missing") from None

    for number, line in enumerate(lines[:MAX_QUESTIONS], start=1):
        if not line.strip():
            continue

        try:
            question = GoldenQuestion.model_validate_json(line)
        except ValidationError as exc:
            raise GoldenError(f"line {number}: {exc.errors()[0]['msg']}")

        if question.id in seen:
            raise GoldenError(f"line {number}: duplicate id {question.id}")

        check_question(question)
        seen.add(question.id)
        questions.append(question)

    return questions


def build_corpus() -> list[Chunk]:
    chunks: list[Chunk] = []

    for book in load_manifest().books:
        chunks.extend(prepare_chunks(book))

    return chunks


def read_cache() -> list[dict] | None:
    try:
        if CORPUS_CACHE.stat().st_mtime < MANIFEST_PATH.stat().st_mtime:
            return None

        lines = CORPUS_CACHE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None

    return [json.loads(line) for line in lines if line]


def load_corpus() -> dict[str, dict]:
    # Rebuilding the chunks takes a few seconds, so they are cached locally.
    rows = read_cache()

    if rows is None:
        rows = [asdict(chunk) for chunk in build_corpus()]
        EVAL_DIR.mkdir(parents=True, exist_ok=True)
        text = "\n".join(json.dumps(row) for row in rows)
        CORPUS_CACHE.write_text(text + "\n", encoding="utf-8")

    corpus = {}

    for row in rows:
        corpus[chunk_id(row["doc_id"], row["chunk_index"])] = row

    return corpus


def stale_labels(
    questions: list[GoldenQuestion], 
    corpus: dict[str, dict]
) -> list[str]:
    problems = []

    for question in questions:
        for label in question.relevant:
            row = corpus.get(label.chunk)

            if row is None:
                problems.append(f"{question.id}: {label.chunk} not found")
            elif row["content_hash"][:8] != label.hash8:
                problems.append(f"{question.id}: {label.chunk} changed")

    return problems
