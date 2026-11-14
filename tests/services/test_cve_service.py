import json
import sqlite3
from pathlib import Path

import pytest

from app.schemas.vulnerabilities import CVSSScore, VulnerabilityRead
from app.services import cve_service as svc
from app.utils import nvd_client


SCHEMA = (
    "CREATE TABLE cves (cve_id TEXT PRIMARY KEY, published TEXT, "
    "modified TEXT, vendor TEXT, vuln_type TEXT, description TEXT, "
    "cvss_version TEXT, cvss_score REAL, cvss_severity TEXT, "
    "cvss_vector TEXT, cwes TEXT, products TEXT, refs TEXT)"
)
ROWS = [
    (
        "CVE-2019-8134", "2019-11-05T23:15:00Z", "2019-11-06T00:00:00Z",
        "adobe", "sql_injection", "Magento SQL injection.",
        None, None, None, None, json.dumps(["CWE-89"]),
        "Magento 2.3", json.dumps(["https://example.com/advisory"]),
    ),
    (
        "CVE-2024-3094", "2024-03-29T17:15:00Z", "2024-04-01T00:00:00Z",
        "tukaani", "backdoor", "xz utils backdoor.",
        "3.1", 10.0, "critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        json.dumps(["CWE-506"]), "xz 5.6.0", json.dumps([]),
    ),
]


@pytest.fixture(autouse=True)
def local_db(tmp_path: Path, settings, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "cve.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute(SCHEMA)
    connection.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    connection.execute(
        "INSERT INTO meta VALUES ('newest_published', '2025-06-10T00:00Z')"
    )
    connection.executemany(f"INSERT INTO cves VALUES ({'?,' * 12}?)", ROWS)
    connection.commit()
    connection.close()

    async def no_exploits(cve_id: str) -> list:
        return []

    monkeypatch.setattr(settings, "cve_db_path", path)
    monkeypatch.setitem(svc._db, "connection", None)
    monkeypatch.setitem(svc._db, "mtime", None)
    monkeypatch.setattr(svc, "search_by_cve", no_exploits)

    return path


def fake_live(status: str, vulnerability=None, calls: list | None = None):
    async def fetch(cve_id: str) -> nvd_client.LiveResult:
        if calls is not None:
            calls.append(cve_id)

        return nvd_client.LiveResult(
            status=status, vulnerability=vulnerability, from_cache=False
        )

    return fetch


@pytest.mark.parametrize(
    "bad", ["CVE-19-1", "CVE-２０１９-8134", "'; DROP TABLE cves", None, 42]
)
def test_hostile_ids_are_rejected(bad):
    with pytest.raises(svc.CveLookupError, match="invalid cve id"):
        svc.normalize_id(bad)


@pytest.mark.anyio
async def test_local_record_with_cvss_needs_no_live_call(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(nvd_client, "fetch_live", fake_live("ok", None, calls))
    result = await svc.lookup_cve(" cve-2024-3094 ")

    assert result.found and result.source == "local"
    assert result.vulnerability.cvss.base_score == 10.0
    assert calls == []


@pytest.mark.anyio
async def test_unknown_id_note_has_dataset_date():
    result = await svc.lookup_cve("CVE-2030-0001", live="never")

    assert result.found is False
    assert "2025-06-10" in result.note
    assert "disabled" in result.note


@pytest.mark.anyio
async def test_auto_goes_live_and_keeps_dataset_fields(monkeypatch):
    live = VulnerabilityRead(
        cve_id="CVE-2019-8134",
        summary="NVD text.",
        cvss=CVSSScore(version="3.1", base_score=8.8, severity="high"),
        cwes=["CWE-89"],
    )
    monkeypatch.setattr(nvd_client, "fetch_live", fake_live("ok", live))
    result = await svc.lookup_cve("CVE-2019-8134")

    assert result.source == "nvd"
    assert result.vulnerability.cvss.base_score == 8.8
    assert result.vulnerability.vendor == "adobe"
    assert result.vulnerability.owasp_categories


@pytest.mark.anyio
async def test_nvd_down_keeps_local_record_with_note(monkeypatch):
    monkeypatch.setattr(
        nvd_client, "fetch_live", fake_live(nvd_client.STATUS_UNAVAILABLE)
    )
    result = await svc.lookup_cve("CVE-2019-8134")

    assert result.found and result.source == "local"
    assert result.vulnerability.cvss is None
    assert "unavailable" in result.note


@pytest.mark.anyio
async def test_missing_database_degrades_to_not_found(
    settings, monkeypatch, tmp_path
):
    monkeypatch.setattr(settings, "cve_db_path", tmp_path / "missing.sqlite3")
    monkeypatch.setitem(svc._db, "connection", None)
    result = await svc.lookup_cve("CVE-2019-8134", live="never")

    assert result.found is False
    assert "unknown" in result.note
