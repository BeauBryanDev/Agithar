import json
import logging

import httpx
import pytest

from app.services import notification_service as svc
from tests.conftest import make_case, make_verdict


TOKEN_FRAGMENT = "AAAAAAAAAAAAAAAAAAAA"


@pytest.fixture(autouse=True)
def clean_state(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    waits: list[float] = []

    async def no_sleep(seconds: float) -> None:
        waits.append(seconds)

    svc._sent_at.clear()
    monkeypatch.setattr(svc.asyncio, "sleep", no_sleep)

    return waits


def ok_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True, "result": {"message_id": 7}})


def test_format_alert_with_verdict_and_incident():
    text = svc.format_alert(make_case(), make_verdict(), incident_id=12)

    assert "HIGH severity" in text
    assert "Incident: 12" in text
    assert "MITRE: T1190" in text
    assert "no review" in text


def test_format_alert_pending_and_not_saved():
    text = svc.format_alert(make_case())

    assert "Verdict: pending" in text
    assert "Incident: not saved" in text


def test_links_are_defanged():
    case = make_case(case_id="see https://evil.example and www.evil.example")
    text = svc.format_alert(case)

    assert "https://" not in text
    assert "hxxps://" in text
    assert "www[.]evil" in text


@pytest.mark.anyio
async def test_send_message_posts_only_allowed_fields(mock_http):
    seen = mock_http(ok_response)
    result = await svc.send_message("hello‮ world\x00 " + "x" * 9000)

    body = json.loads(seen[0].content)

    assert result == {"sent": True, "message_id": 7}
    assert set(body) == {"chat_id", "text", "disable_web_page_preview"}
    assert body["chat_id"] == "424242"
    assert "‮" not in body["text"] and "\x00" not in body["text"]
    assert len(body["text"]) <= svc.MAX_MESSAGE_CHARS + 32


@pytest.mark.anyio
async def test_429_is_retried_with_retry_after(mock_http, clean_state):
    replies = [
        httpx.Response(
            429, json={"ok": False, "parameters": {"retry_after": 3}}
        ),
        httpx.Response(200, json={"ok": True, "result": {"message_id": 8}}),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        return replies.pop(0)

    seen = mock_http(handler)
    result = await svc.send_message("retry me")

    assert result["message_id"] == 8
    assert len(seen) == 2
    assert clean_state == [3.0]


@pytest.mark.anyio
async def test_401_fails_at_once_without_leaking_token(mock_http, caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"ok": False})

    seen = mock_http(handler)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(svc.NotificationError) as info:
            await svc.send_message("hi")

    assert len(seen) == 1
    assert TOKEN_FRAGMENT not in str(info.value)
    assert TOKEN_FRAGMENT not in caplog.text


@pytest.mark.anyio
async def test_network_error_never_leaks_token(mock_http, caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout(f"timed out for {request.url}")

    mock_http(handler)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(svc.NotificationError) as info:
            await svc.send_message("hi")

    assert info.value.__cause__ is None
    assert TOKEN_FRAGMENT not in str(info.value)
    assert TOKEN_FRAGMENT not in caplog.text


@pytest.mark.anyio
async def test_flood_cap(mock_http):
    mock_http(ok_response)

    for _ in range(svc.MAX_MESSAGES_PER_MINUTE):
        await svc.send_message("flood")

    with pytest.raises(svc.NotificationError, match="rate limit"):
        await svc.send_message("one too many")


@pytest.mark.anyio
async def test_not_configured(settings, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "telegram_bot_token", None)

    with pytest.raises(svc.NotificationError, match="not configured"):
        await svc.send_message("hi")
