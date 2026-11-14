import math

import pytest

from app.rag import eval_metrics as m


RANKED = ["a", "x", "b", "y", "c"]
RELEVANT = {"a", "b", "c", "d"}


def test_perfect_ranking_scores_one():
    grades = {"a": 2, "b": 1}
    result = m.question_metrics(["a", "b", "z"], grades)

    assert result["hit@1"] == 1.0
    assert result["mrr"] == 1.0
    assert result["map"] == 1.0
    assert result["ndcg@3"] == pytest.approx(1.0)
    assert result["recall@3"] == 1.0


def test_no_relevant_chunk_retrieved():
    result = m.question_metrics(["x", "y", "z"], {"a": 2})

    assert result["hit@10"] == 0.0
    assert result["mrr"] == 0.0
    assert result["ndcg@10"] == 0.0
    assert result["precision@3"] == 0.0


def test_precision_and_recall_by_hand():
    assert m.precision_at_k(RANKED, RELEVANT, 3) == pytest.approx(2 / 3)
    assert m.recall_at_k(RANKED, RELEVANT, 3) == pytest.approx(2 / 4)
    assert m.precision_at_k(RANKED, RELEVANT, 10) == pytest.approx(3 / 10)
    assert m.recall_at_k(RANKED, RELEVANT, 10) == pytest.approx(3 / 4)


def test_reciprocal_rank_uses_first_relevant():
    assert m.reciprocal_rank(["x", "y", "a"], RELEVANT, 10) == pytest.approx(
        1 / 3
    )
    assert m.reciprocal_rank(["x", "y", "a"], RELEVANT, 2) == 0.0


def test_average_precision_by_hand():
    # Relevant at ranks 1, 3, 5: (1/1 + 2/3 + 3/5) / min(4, 10).
    expected = (1 + 2 / 3 + 3 / 5) / 4

    assert m.average_precision(RANKED, RELEVANT, 10) == pytest.approx(expected)


def test_graded_ndcg_by_hand():
    grades = {"a": 1, "b": 2}
    gains = (2 ** 1 - 1) / math.log2(2) + (2 ** 2 - 1) / math.log2(4)
    ideal = (2 ** 2 - 1) / math.log2(2) + (2 ** 1 - 1) / math.log2(3)

    assert m.ndcg_at_k(["a", "x", "b"], grades, 3) == pytest.approx(
        gains / ideal
    )


def test_duplicates_count_once():
    ranked = ["a", "a", "a", "b"]

    assert m.top(ranked, 2) == ["a", "b"]
    assert m.precision_at_k(ranked, {"a", "b"}, 2) == 1.0


def test_k_larger_than_results():
    assert m.precision_at_k(["a"], {"a"}, 10) == pytest.approx(0.1)
    assert m.recall_at_k(["a"], {"a"}, 10) == 1.0


def test_answer_hit_needs_grade_two():
    result = m.question_metrics(["p", "q"], {"p": 1, "z": 2})

    assert result["hit@1"] == 1.0
    assert result["answer_hit@1"] == 0.0


def test_r_precision_caps_at_depth():
    assert m.r_precision(["a", "x"], {"a", "b"}, 10) == pytest.approx(0.5)
    assert m.r_precision(["x"], set(), 10) == 0.0


def test_auc_and_threshold_table():
    assert m.auc([0.9, 0.8], [0.1, 0.2]) == 1.0
    assert m.auc([0.5], [0.5]) == 0.5
    assert m.auc([], [0.1]) is None

    rows = m.threshold_table([0.2, 0.35], [0.5, 0.3, None], [0.25, 0.4])

    assert rows[0] == {
        "min_score": 0.25, "negatives_answered": 1, "questions_lost": 1,
    }
    assert rows[1]["questions_lost"] == 2


def test_average_rounds_means():
    rows = [{"hit@1": 1.0, "mrr": 0.5}, {"hit@1": 0.0, "mrr": 1 / 3}]

    assert m.average(rows) == {"hit@1": 0.5, "mrr": 0.4167}
    assert m.average([]) == {}
