import httpx
import pytest

from app.services import abuse_ip_service as svc


def never(request: httpx.Request) -> httpx.Response:
    raise AssertionError("no request expected")


@pytest.mark.anyio
async def test_check_ip_sends_key_in_header(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Key"] == "abuse-test-key-0000"
        assert "abuse-test-key" not in str(request.url)
        return httpx.Response(
            200,
            json={"data": {
                "abuseConfidenceScore": 87,
                "totalReports": 40,
                "countryCode": "NL​",
                "isWhitelisted": False,
            }},
        )

    seen = mock_http(handler)
    result = await svc.check_ip("8.8.8.8")

    assert len(seen) == 1
    assert result["abuse_confidence_score"] == 87
    assert result["country_code"] == "NL"


@pytest.mark.anyio
@pytest.mark.parametrize("bad", ["fe80::1%eth0", "not-an-ip", "1.2.3.4/24"])
async def test_invalid_ip_rejected_before_request(mock_http, bad):
    seen = mock_http(never)

    with pytest.raises(svc.AbuseIPLookupError, match="invalid ip"):
        await svc.check_ip(bad)

    assert seen == []


@pytest.mark.anyio
async def test_missing_key(settings, monkeypatch):
    monkeypatch.setattr(settings, "abuseipdb_api_key", None)

    with pytest.raises(svc.AbuseIPLookupError, match="not configured"):
        await svc.check_ip("8.8.8.8")


@pytest.mark.anyio
async def test_non_json_body(mock_http):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    mock_http(handler)

    with pytest.raises(svc.AbuseIPLookupError, match="invalid body"):
        await svc.check_ip("8.8.8.8")
