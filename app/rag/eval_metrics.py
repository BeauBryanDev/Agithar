import math
from statistics import mean

CUTOFFS = (1, 3, 5, 10)


def relevant_set(grades: dict[str, int], min_grade: int = 1) -> set[str]:
    return {chunk for chunk, grade in grades.items() if grade >= min_grade}


def top(ranked: list[str], k: int) -> list[str]:
    # Duplicates in a ranking count once, at their first position.
    seen: list[str] = []

    for chunk in ranked:
        if chunk not in seen:
            seen.append(chunk)

        if len(seen) == k:
            break

    return seen


def hit_at_k(ranked: list[str], relevant: set[str], k: int) -> float:
    return float(any(chunk in relevant for chunk in top(ranked, k)))


def precision_at_k(ranked: list[str], relevant: set[str], k: int) -> float:
    found = sum(1 for chunk in top(ranked, k) if chunk in relevant)

    return found / k


def recall_at_k(ranked: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0

    found = sum(1 for chunk in top(ranked, k) if chunk in relevant)

    return found / len(relevant)


def reciprocal_rank(ranked: list[str], relevant: set[str], k: int) -> float:
    for rank, chunk in enumerate(top(ranked, k), start=1):
        if chunk in relevant:
            return 1.0 / rank

    return 0.0


def average_precision(ranked: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0

    found = 0
    total = 0.0

    for rank, chunk in enumerate(top(ranked, k), start=1):
        if chunk in relevant:
            found += 1
            total += found / rank

    return total / min(len(relevant), k)


def r_precision(ranked: list[str], relevant: set[str], k: int) -> float:
    # Precision at R = number of relevant chunks, capped at the depth.
    depth = min(len(relevant), k)

    if depth == 0:
        return 0.0

    return precision_at_k(ranked, relevant, depth)


def dcg(gains: list[int]) -> float:
    total = 0.0

    for rank, grade in enumerate(gains, start=1):
        total += (2 ** grade - 1) / math.log2(rank + 1)

    return total


def ndcg_at_k(ranked: list[str], grades: dict[str, int], k: int) -> float:
    ideal = dcg(sorted(grades.values(), reverse=True)[:k])

    if ideal == 0:
        return 0.0

    gains = [grades.get(chunk, 0) for chunk in top(ranked, k)]

    return dcg(gains) / ideal


def question_metrics(
    ranked: list[str], grades: dict[str, int]
) -> dict[str, float]:
    relevant = relevant_set(grades)
    answers = relevant_set(grades, min_grade=2)
    depth = max(CUTOFFS)
    result = {
        "mrr": reciprocal_rank(ranked, relevant, depth),
        "map": average_precision(ranked, relevant, depth),
        "r_precision": r_precision(ranked, relevant, depth),
    }

    for k in CUTOFFS:
        result[f"hit@{k}"] = hit_at_k(ranked, relevant, k)
        result[f"answer_hit@{k}"] = hit_at_k(ranked, answers, k)
        result[f"precision@{k}"] = precision_at_k(ranked, relevant, k)
        result[f"recall@{k}"] = recall_at_k(ranked, relevant, k)
        result[f"ndcg@{k}"] = ndcg_at_k(ranked, grades, k)

    return result


def average(rows: list[dict[str, float]]) -> dict[str, float]:
    if not rows:
        return {}

    return {key: round(mean(row[key] for row in rows), 4) for key in rows[0]}


def auc(positives: list[float], negatives: list[float]) -> float | None:
    # Probability that a relevant hit outscores an irrelevant one.
    if not positives or not negatives:
        return None

    wins = 0.0

    for pos in positives:
        for neg in negatives:
            wins += 1.0 if pos > neg else 0.5 if pos == neg else 0.0

    return round(wins / (len(positives) * len(negatives)), 4)


def percentile(values: list[float], share: float) -> float:
    ordered = sorted(values)
    index = min(int(share * len(ordered)), len(ordered) - 1)

    return ordered[index]


def threshold_table(
    negative_tops: list[float],
    best_relevant: list[float | None],
    thresholds: list[float],
) -> list[dict[str, float]]:
    # For each cutoff: negatives that would still return something, and
    # in-scope questions that would lose every relevant passage.
    rows = []

    for cutoff in thresholds:
        alarms = sum(1 for score in negative_tops if score >= cutoff)
        lost = sum(
            1 for score in best_relevant if score is None or score < cutoff
        )
        rows.append({
            "min_score": cutoff,
            "negatives_answered": alarms,
            "questions_lost": lost,
        })

    return rows
