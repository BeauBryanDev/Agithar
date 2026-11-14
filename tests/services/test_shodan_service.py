import logging

import httpx
import pytest

from app.services import shodan_service as svc


@pytest.mark.anyio
async def test_check_ip_caps_and_cleans(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "org": "Evil‮Corp",
                "ports": [22, "80", True, 443] + list(range(1000, 1200)),
                "hostnames": ["a.example"] * 50,
                "vulns": ["CVE-2024-3094"],
            },
        )

    mock_http(handler)
    result = await svc.check_ip("8.8.8.8")

    assert result["found"] is True
    assert "‮" not in result["org"]
    assert result["ports"][:2] == [22, 443]
    assert len(result["ports"]) <= svc.MAX_PORTS
    assert len(result["hostnames"]) <= svc.MAX_HOSTNAMES


@pytest.mark.anyio
async def test_404_is_not_found(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "No information"})

    mock_http(handler)

    assert await svc.check_ip("8.8.8.8") == {"ip": "8.8.8.8", "found": False}


@pytest.mark.anyio
async def test_key_never_in_error_or_app_logs(mock_http, caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(f"timeout on {request.url}")

    mock_http(handler)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(svc.ShodanLookupError) as info:
            await svc.check_ip("8.8.8.8")

    assert "shodan-test-key" not in str(info.value)
    assert "shodan-test-key" not in caplog.text
    assert info.value.__cause__ is None


@pytest.mark.anyio
async def test_missing_key(settings, monkeypatch):
    monkeypatch.setattr(settings, "shodan_api_key", None)

    with pytest.raises(svc.ShodanLookupError, match="not configured"):
        await svc.check_ip("8.8.8.8")
