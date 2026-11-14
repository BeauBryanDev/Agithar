import time
from datetime import datetime, timezone
from statistics import median
from typing import Any

from app.core.config import get_settings
from app.rag import eval_metrics as m
from app.rag.golden import GoldenQuestion, chunk_id
from app.rag.retriever import Hit, search

RAW_DEPTH = 10
AGENT_DEPTH = 3
AGENT_KEYS = ("hit@3", "answer_hit@3", "precision@3", "recall@3", "ndcg@3")
THRESHOLDS = [0.25, 0.30, 0.35, 0.40, 0.45, 0.50]


def timed_search(question: GoldenQuestion, depth: int, dedupe: bool):
    start = time.perf_counter()
    hits = search(question.question, question.namespace, top_k=depth,
                  dedupe=dedupe)

    return hits, (time.perf_counter() - start) * 1000


def ids_of(hits: list[Hit]) -> list[str]:
    return [chunk_id(hit.doc_id, hit.chunk_index) for hit in hits]


def page_spans(question: GoldenQuestion, corpus: dict) -> list[tuple]:
    spans = [tuple(span) for span in question.pages]

    for label in question.relevant:
        row = corpus[label.chunk]
        spans.append((row["doc_id"], row["page_start"], row["page_end"]))

    return spans


def lenient(hits: list[Hit], spans: list[tuple], k: int) -> tuple[float, float]:
    page_hit = 0.0
    book_hit = 0.0

    for hit in hits[:k]:
        for doc_id, first, last in spans:
            if hit.doc_id == doc_id:
                book_hit = 1.0

                if hit.page_start <= last and first <= hit.page_end:
                    page_hit = 1.0

    return page_hit, book_hit


def score_question(question: GoldenQuestion, corpus: dict) -> dict[str, Any]:
    grades = question.grades()
    raw, raw_ms = timed_search(question, RAW_DEPTH, dedupe=False)
    agent, agent_ms = timed_search(question, AGENT_DEPTH, dedupe=True)
    ranked = ids_of(raw)
    row: dict[str, Any] = {
        "id": question.id,
        "namespace": question.namespace,
        "type": question.type,
        "ranked": ranked,
        "scores": [round(hit.score, 4) for hit in raw],
        "agent_ranked": ids_of(agent),
        "latency_ms": [round(raw_ms, 1), round(agent_ms, 1)],
    }

    if question.type == "negative":
        row["top_score"] = row["scores"][0] if raw else 0.0
        return row

    spans = page_spans(question, corpus)
    row["metrics"] = m.question_metrics(ranked, grades)
    row["metrics"]["page_hit@3"], row["metrics"]["book_hit@3"] = lenient(
        raw, spans, 3
    )
    agent_metrics = m.question_metrics(ids_of(agent), grades)
    row["agent"] = {key: agent_metrics[key] for key in AGENT_KEYS}
    relevant = m.relevant_set(grades)
    row["relevant_scores"] = [
        s for c, s in zip(ranked, row["scores"]) if c in relevant
    ]
    row["other_scores"] = [
        s for c, s in zip(ranked, row["scores"]) if c not in relevant
    ]

    return row


def group_average(rows: list[dict], field: str, key: str) -> dict:
    groups: dict[str, list[dict]] = {}

    for row in rows:
        groups.setdefault(row[field], []).append(row[key])

    return {name: m.average(items) for name, items in sorted(groups.items())}


def calibration(scored: list[dict], negatives: list[dict]) -> dict:
    positives = [s for row in scored for s in row["relevant_scores"]]
    others = [s for row in scored for s in row["other_scores"]]
    negative_tops = [row["top_score"] for row in negatives]
    best = [max(row["relevant_scores"], default=None) for row in scored]

    return {
        "auc_relevant_vs_other": m.auc(positives, others),
        "relevant_score_median": round(median(positives), 4)
        if positives else None,
        "other_score_median": round(median(others), 4) if others else None,
        "negative_top_scores": negative_tops,
        "thresholds": m.threshold_table(negative_tops, best, THRESHOLDS),
    }


def latency(rows: list[dict]) -> dict:
    values = [ms for row in rows for ms in row["latency_ms"]]

    return {
        "p50_ms": round(m.percentile(values, 0.5), 1),
        "p95_ms": round(m.percentile(values, 0.95), 1),
    }


def run_eval(questions: list[GoldenQuestion], corpus: dict) -> dict:
    rows = [score_question(question, corpus) for question in questions]
    scored = [row for row in rows if "metrics" in row]
    negatives = [row for row in rows if "metrics" not in row]
    settings = get_settings()

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "index": settings.pinecone_index_name,
            "embedding_model": settings.embedding_model,
            "raw_depth": RAW_DEPTH,
            "agent_depth": AGENT_DEPTH,
            "questions": len(rows),
            "in_scope": len(scored),
            "negatives": len(negatives),
        },
        "overall": m.average([row["metrics"] for row in scored]),
        "agent_view": m.average([row["agent"] for row in scored]),
        "by_namespace": group_average(scored, "namespace", "metrics"),
        "by_type": group_average(scored, "type", "metrics"),
        "calibration": calibration(scored, negatives),
        "latency": latency(rows),
        "questions": rows,
    }
