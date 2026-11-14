import logging

import httpx
import pytest

from app.services import virustotal_service as svc


SHA256 = "A" * 64


def stats_body(**stats) -> dict:
    return {"data": {"attributes": {"last_analysis_stats": stats}}}


@pytest.mark.parametrize("bad", ["abc", "g" * 64, SHA256 + "0", "../etc"])
def test_validate_hash_rejects_junk(bad):
    with pytest.raises(svc.VirusTotalLookupError):
        svc.validate_hash(bad)


def test_validate_hash_lowercases_and_url_rules():
    assert svc.validate_hash(f"  {SHA256} ") == "a" * 64
    assert svc.validate_url("https://example.com/a") == "https://example.com/a"

    too_long = "https://" + "a" * 2050

    for bad in ["ftp://example.com", "javascript:alert(1)", too_long]:
        with pytest.raises(svc.VirusTotalLookupError):
            svc.validate_url(bad)


def test_extract_stats_ignores_junk_counts():
    body = stats_body(malicious=True, suspicious="7", harmless=12)

    assert svc.extract_stats(body) == {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 12,
        "undetected": 0,
    }
    assert svc.extract_stats({"data": "garbage"})["malicious"] == 0


@pytest.mark.anyio
async def test_check_hash_sanitizes_names(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-apikey"] == "vt-test-key-0000"
        body = stats_body(malicious=3)
        body["data"]["attributes"]["names"] = ["evil‮.exe"] * 9
        return httpx.Response(200, json=body)

    mock_http(handler)
    result = await svc.check_hash(SHA256)

    assert result["malicious"] == 3
    assert len(result["names"]) == svc.MAX_NAMES
    assert "‮" not in result["names"][0]


@pytest.mark.anyio
async def test_url_lookup_failure_never_leaks_the_url(mock_http, caplog):
    secret_url = "https://victim.example/reset?token=s3cr3t"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    mock_http(handler)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(svc.VirusTotalLookupError) as info:
            await svc.check_url(secret_url)

    assert "s3cr3t" not in str(info.value)
    assert "s3cr3t" not in caplog.text


@pytest.mark.anyio
async def test_missing_key(settings, monkeypatch):
    monkeypatch.setattr(settings, "virustotal_api_key", None)

    with pytest.raises(svc.VirusTotalLookupError, match="not configured"):
        await svc.check_ip("8.8.8.8")
