import subprocess

import pytest

from app.services import os_service as svc


class FakeRun:
    def __init__(self, returncode: int = 0, stdout: str = "active\n",
                 error: Exception | None = None) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.error = error
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str], **kwargs) -> object:
        self.calls.append(args)
        assert kwargs.get("shell") is not True

        if self.error is not None:
            raise self.error

        return subprocess.CompletedProcess(
            args, self.returncode, self.stdout, ""
        )


@pytest.mark.parametrize(
    "unit", ["sshd.service", "--help", "nginx.service; reboot", None, ["x"]]
)
def test_unlisted_units_never_reach_systemctl(monkeypatch, unit):
    fake = FakeRun()
    monkeypatch.setattr(svc.subprocess, "run", fake)

    with pytest.raises(svc.OsQueryError, match="not monitored"):
        svc.get_service_status(unit)

    assert fake.calls == []


@pytest.mark.parametrize(
    "returncode, stdout, expected",
    [
        (0, "active\n", "active"),
        (3, "inactive\n", "inactive"),
        (4, "inactive\n", "not-found"),
        (0, "pwned\x1b[31m\n", "unknown"),
    ],
)
def test_state_mapping(monkeypatch, returncode, stdout, expected):
    fake = FakeRun(returncode, stdout)
    monkeypatch.setattr(svc.subprocess, "run", fake)

    assert svc.get_service_status("nginx.service") == expected
    assert fake.calls == [["systemctl", "is-active", "nginx.service"]]


def test_timeout_raises_and_snapshot_reports_unknown(monkeypatch):
    fake = FakeRun(error=subprocess.TimeoutExpired("systemctl", 5))
    monkeypatch.setattr(svc.subprocess, "run", fake)

    with pytest.raises(svc.OsQueryError, match="timed out"):
        svc.get_service_status("nginx.service")

    statuses = svc.get_sibling_status()

    assert set(statuses.values()) == {"unknown"}
