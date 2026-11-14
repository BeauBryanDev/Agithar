from app.sensors.base import SensorResult
from app.services import ingest_service as svc


def result(sensor: str, score: float) -> SensorResult:
    return SensorResult(sensor=sensor, score=score, is_anomalous=True)


def test_path_of_strips_query_and_fragment():
    assert svc.path_of("/login?next=/admin&token=abc#top") == "/login"
    assert svc.path_of("") is None
    assert svc.path_of(None) is None
    assert len(svc.path_of("/" + "a" * 5000)) <= 232


def test_summarise_uses_correlator_rules():
    out = svc.Outcome()
    lone = out.source("198.51.100.1")
    lone.flag(result("http_payload_sensor", 0.95))
    both = out.source("203.0.113.9")
    both.flag(result("http_payload_sensor", 0.97))
    both.flag(result("http_payload_sensor", 0.80))
    both.flag(result("recon_sensor", 0.99))
    out.source("192.0.2.1")
    rows, severity, composite = svc.summarise(out)

    assert severity == "high"
    assert rows[0].source == "203.0.113.9"
    assert rows[0].sensors == ["http_payload_sensor", "recon_sensor"]
    assert rows[1].severity == "medium"
    assert len(rows) == 2
    assert composite == rows[0].composite_score


def test_empty_outcome_is_low():
    assert svc.summarise(svc.Outcome()) == ([], "low", 0.0)
