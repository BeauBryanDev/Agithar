import pytest

from app.services import sigma_service as svc


def test_fts_expression_quotes_every_word():
    expression = svc.fts_expression('ssh NEAR(brute) OR "x" *', " AND ")

    assert expression == '"ssh" AND "near" AND "brute" AND "or"'
    assert svc.fts_expression("!!! ??", " OR ") is None


@pytest.mark.parametrize("platform", ["windows", "macos", "linux; DROP"])
def test_unindexed_platforms_rejected(platform):
    with pytest.raises(svc.SigmaLookupError, match="unknown platform"):
        svc.find_rules("T1110", platform=platform)


def test_parent_technique_matches_sub_techniques(settings):
    if not settings.sigma_db_path.exists():
        pytest.skip("sigma index not built")

    result = svc.find_rules("t1110", platform="any")
    techniques = " ".join(" ".join(r["techniques"]) for r in result["rules"])

    assert result["query_type"] == "technique"
    assert result["total"] >= len(result["rules"]) > 0
    assert "T1110" in techniques
    assert "none of them is deployed" in result["attribution"]["note"]
