import pytest

from app.services import sensor_service as svc


class FakeLive:
    def by_sensor(self, now: float) -> dict:
        return {"recon_sensor": {"anomalies": 2, "last": now, "events": [1]}}


class FakeFeed:
    live = FakeLive()

    def snapshot(self) -> dict:
        return {"counters": {"windows_scored": 40, "recon_anomalies": 3}}


def test_activity_with_and_without_feed():
    recon = svc.activity("recon_sensor", FakeFeed(), 100.0)
    guard = svc.activity("net_guard", FakeFeed(), 100.0)

    assert recon["scored"] == 40 and recon["flagged"] == 3
    assert recon["flagged_last_hour"] == 2
    assert guard["scored"] is None and guard["flagged_last_hour"] == 0
    assert svc.activity("recon_sensor", None, 100.0)["recent"] == []


@pytest.mark.models
def test_overview_with_real_sensors():
    from app.sensors.registry import load_default_registry

    data = svc.overview(load_default_registry(), None)

    assert data["feed_running"] is False
    assert len(data["sensors"]) == 5
    assert data["all_healthy"] is True
