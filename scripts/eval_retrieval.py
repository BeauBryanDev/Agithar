import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.rag.embed import EmbedError  # noqa: E402
from app.rag.eval_run import run_eval  # noqa: E402
from app.rag.golden import (  # noqa: E402
    EVAL_DIR,
    GoldenError,
    load_corpus,
    load_golden,
    stale_labels,
)
from app.rag.indexer import IndexerError  # noqa: E402
from app.rag.retriever import RetrieverError  # noqa: E402

SUMMARY_KEYS = (
    "hit@1", "hit@3", "hit@5", "hit@10", "answer_hit@3", "mrr", "map",
    "ndcg@3", "ndcg@10", "precision@3", "recall@3", "recall@10",
    "r_precision", "page_hit@3", "book_hit@3",
)
GROUP_KEYS = ("hit@3", "mrr", "ndcg@10", "recall@10")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RAG retrieval evaluation")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--namespace")
    parser.add_argument("--type")
    parser.add_argument("--compare", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="validate the golden set only, no API calls")

    return parser.parse_args()


def select(questions, args) -> list:
    chosen = []

    for question in questions:
        if args.namespace and question.namespace != args.namespace:
            continue

        if args.type and question.type != args.type:
            continue

        chosen.append(question)

    return chosen


def print_table(title: str, values: dict, keys) -> None:
    print(f"\n{title}")

    for key in keys:
        if key in values:
            print(f"  {key:14} {values[key]:.3f}")


def print_groups(title: str, groups: dict) -> None:
    print(f"\n{title}")
    print("  " + " " * 14 + "".join(f"{key:>11}" for key in GROUP_KEYS))

    for name, values in groups.items():
        cells = "".join(f"{values[key]:>11.3f}" for key in GROUP_KEYS)
        print(f"  {name:14}{cells}")


def print_misses(report: dict, verbose: bool) -> None:
    print("\nper question (rank of first relevant chunk in the top 10)")

    for row in report["questions"]:
        if "metrics" not in row:
            print(f"  {row['id']}  negative, top score {row['top_score']:.3f}")
            continue

        mrr = row["metrics"]["mrr"]
        rank = round(1 / mrr) if mrr else None
        status = f"rank {rank}" if rank else "MISS"

        if verbose or rank is None or rank > 3:
            print(f"  {row['id']}  {status:8} [{row['type']}]")

        if verbose:
            for chunk, score in zip(row["ranked"], row["scores"]):
                print(f"      {score:.3f} {chunk}")


def print_calibration(cal: dict) -> None:
    print("\nscore calibration (cosine, raw top 10)")
    print(f"  AUC relevant vs other hits: {cal['auc_relevant_vs_other']}")
    print(f"  median relevant {cal['relevant_score_median']}, "
          f"median other {cal['other_score_median']}")
    tops = ", ".join(f"{s:.3f}" for s in cal["negative_top_scores"])
    print(f"  negative questions, top score: {tops}")

    for row in cal["thresholds"]:
        print(f"  min_score {row['min_score']:.2f}: "
              f"{row['negatives_answered']} negatives still answered, "
              f"{row['questions_lost']} in-scope questions lose every "
              f"relevant passage")


def print_compare(report: dict, path: Path) -> None:
    try:
        old = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SystemExit("error: cannot read the comparison report")

    print(f"\nchange against {path.name}")

    for section in ("overall", "agent_view"):
        for key, value in report[section].items():
            before = old.get(section, {}).get(key)

            if before is not None and abs(value - before) >= 0.0005:
                print(f"  {section}.{key:14} {before:.3f} -> {value:.3f} "
                      f"({value - before:+.3f})")


def save(report: dict) -> Path:
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = EVAL_DIR / f"run_{stamp}.json"
    path.write_text(json.dumps(report, indent=1), encoding="utf-8")

    return path


def main() -> None:
    args = parse_args()

    try:
        questions = select(load_golden(), args)
    except GoldenError as exc:
        raise SystemExit(f"error: {exc}")

    corpus = load_corpus()
    stale = stale_labels(questions, corpus)

    for problem in stale:
        print(f"STALE {problem}")

    if stale:
        raise SystemExit("error: fix the stale labels before evaluating")

    print(f"golden set ok: {len(questions)} questions")

    if args.check:
        return

    try:
        report = run_eval(questions, corpus)
    except (RetrieverError, EmbedError, IndexerError) as exc:
        raise SystemExit(f"error: {exc}")

    print_table("raw ranking (top 10, no dedupe)", report["overall"],
                SUMMARY_KEYS)
    print_table("what Agithar receives (top 3, deduped)",
                report["agent_view"], report["agent_view"].keys())
    print_groups("by namespace", report["by_namespace"])
    print_groups("by question type", report["by_type"])
    print_calibration(report["calibration"])
    print(f"\nlatency per search: {report['latency']}")
    print_misses(report, args.verbose)

    if args.compare:
        print_compare(report, args.compare)

    print(f"\nreport saved to {save(report)}")


if __name__ == "__main__":
    main()
