import pytest

from app.rag.mitre_attack import MitreError
from app.schemas.analysis import AnalyzeRequest
from app.services import analysis_service as svc
from tests.conftest import FakeRegistry, make_verdict


ACCESS_LINE = (
    '203.0.113.9 - - [14/Nov/2026:10:00:00 +0000] "GET /index.php?id=1 '
    'HTTP/1.1" 404 512 "-" "dirb/2.22"'
)


@pytest.mark.parametrize(
    "severity, confidence, expected",
    [
        ("high", 0.99, "needs_human"),
        ("medium", 0.5, "needs_human"),
        ("medium", 0.9, "confirmed"),
        ("low", 0.4, "confirmed"),
    ],
)
def test_enforce_verdict_escalation_rule(severity, confidence, expected):
    verdict = make_verdict(confidence=confidence)
    enforced = svc.enforce_verdict(verdict, severity)

    assert enforced.verdict == expected
    assert enforced.needs_human == (expected == "needs_human")


def test_enforce_verdict_never_downgrades_needs_human():
    verdict = make_verdict(verdict="needs_human", needs_human=True)

    assert svc.enforce_verdict(verdict, "low").needs_human is True


def fake_check(status: str, **extra):
    def check(technique: str) -> dict:
        return {"status": status, "id": technique, **extra}

    return check


def fake_version() -> str:
    return "19.2"


def test_mitre_active_technique_unchanged(monkeypatch):
    monkeypatch.setattr(svc, "check_technique", fake_check("active"))
    verdict = make_verdict()

    assert svc.check_mitre_technique(verdict) == verdict


def test_mitre_revoked_and_unknown_are_corrected(monkeypatch):
    monkeypatch.setattr(svc, "attack_version", fake_version)
    monkeypatch.setattr(
        svc,
        "check_technique",
        fake_check(
            "revoked", replacement="T1027.005", replacement_name="Indicator"
        ),
    )
    revoked = svc.check_mitre_technique(make_verdict(mitre_technique="T1066"))

    monkeypatch.setattr(svc, "check_technique", fake_check("unknown"))
    unknown = svc.check_mitre_technique(make_verdict(mitre_technique="T9999"))

    assert revoked.mitre_technique == "T1027.005"
    assert "revoked" in revoked.summary
    assert unknown.mitre_technique is None
    assert "does not exist" in unknown.summary


def test_mitre_index_down_keeps_technique(monkeypatch):
    def broken(technique: str) -> dict:
        raise MitreError("index missing")

    monkeypatch.setattr(svc, "check_technique", broken)
    checked = svc.check_mitre_technique(make_verdict())

    assert checked.mitre_technique == "T1190"
    assert "could not be verified" in checked.summary


@pytest.mark.parametrize(
    "text, sensor",
    [
        ("E5 E22 E11 E9", "log_sentinel"),
        (ACCESS_LINE, "recon_sensor"),
        ("GET /search?q=<script> HTTP/1.1", "http_payload_sensor"),
    ],
)
def test_input_is_routed_to_the_right_sensor(text, sensor):
    sensors = {job.sensor for job in svc.jobs_from_input(text)}

    assert sensor in sensors


def test_analyze_does_not_echo_raw_input():
    registry = FakeRegistry({"http_payload_sensor": 0.99})
    payload = "GET /x?q=' OR '1'='1 HTTP/1.1"
    response = svc.analyze(registry, AnalyzeRequest(input=payload))

    assert "medium" in response.text
    assert "OR '1'" not in response.text
    assert response.evidence


def test_analyze_raises_when_no_sensor_fits():
    registry = FakeRegistry({"net_guard": 0.9})

    with pytest.raises(ValueError):
        svc.analyze(registry, AnalyzeRequest(input="hello there"))
