from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from app.services import dashboard_service as svc


NOW = datetime(2026, 11, 14, 12, 30, tzinfo=timezone.utc)


@dataclass
class Row:
    created_at: datetime
    composite_score: float = 0.7
    severity: str = "medium"
    status: str = "open"
    contributing_sensors: list | None = None
    verdict: object = None


@pytest.fixture(autouse=True)
def no_mitre(monkeypatch):
    def lookup(technique: str) -> dict:
        return {"name": "Exploit Public-Facing Application"}

    monkeypatch.setattr(svc.mitre_attack, "lookup", lookup)


def test_hourly_timeline_fills_empty_buckets():
    then = NOW - timedelta(hours=2)
    rows = [Row(then, 0.6), Row(then, 0.9)]
    points = svc.build_timeline(rows, NOW, 24)
    busy = [p for p in points if p.incidents]

    assert len(points) == 25
    assert len(busy) == 1
    assert busy[0].score == 0.9 and busy[0].incidents == 2


def test_daily_buckets_and_naive_datetimes():
    naive = (NOW - timedelta(days=3)).replace(tzinfo=None)
    points = svc.build_timeline([Row(naive, 1.7)], NOW, 24 * 7)

    assert all(p.timestamp.hour == 0 for p in points)
    assert max(p.score for p in points) == 1.0


def test_mean_confidence_ignores_junk():
    rows = [
        Row(NOW, verdict={"confidence": 0.8}),
        Row(NOW, verdict={"confidence": "high"}),
        Row(NOW, verdict="not a dict"),
        Row(NOW, verdict={"confidence": 0.4}),
    ]

    assert svc.mean_confidence(rows) == 0.6
    assert svc.mean_confidence([Row(NOW)]) is None


def test_build_dashboard_counts():
    rows = [
        Row(NOW, severity="high", status="confirmed",
            contributing_sensors=["recon_sensor"],
            verdict={"mitre_technique": "T1190", "confidence": 0.9}),
        Row(NOW, severity="low", contributing_sensors=None),
    ]
    data = svc.build_dashboard(rows, NOW, 24)

    assert data.total_incidents == 2
    assert data.severity_distribution["high"] == 1
    assert data.status_counts["confirmed"] == 1
    assert data.by_sensor[0].sensor == "recon_sensor"
    assert data.top_techniques[0].name.startswith("Exploit")
