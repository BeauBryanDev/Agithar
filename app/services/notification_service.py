import asyncio
import re
import threading
import time
from collections import deque
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.analysis import AgentVerdict
from app.security.sanitize import sanitize_string

API_URL = "https://api.telegram.org/bot{token}/sendMessage"
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_MESSAGE_CHARS = 3500
MAX_FIELD_CHARS = 120
MAX_SENSORS = 10
MAX_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 2.0
MAX_RETRY_WAIT_SECONDS = 30.0
MAX_MESSAGES_PER_MINUTE = 30
RATE_WINDOW_SECONDS = 60.0
SERVER_ERROR_FLOOR = 500
HTTP_TOO_MANY = 429
URL_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)
WWW_PREFIX = re.compile(r"\bwww\.", re.IGNORECASE)


logger = get_logger("services.notification")

_sent_at: deque[float] = deque()
_lock = threading.Lock()


class NotificationError(Exception):
    pass


def clean(value: Any, 
          limit: int = MAX_FIELD_CHARS
          ) -> str:
    return sanitize_string(str(value), limit)


def defang(text: str) -> str:
    # Telegram turns links in plain text into clickable ones.
    text = URL_SCHEME.sub(r"hxxp\1://", text)

    return WWW_PREFIX.sub("www[.]", text)


def verdict_lines(verdict: AgentVerdict | None) -> list[str]:
    if verdict is None:
        return ["Verdict: pending"]

    review = "human review required" if verdict.needs_human else "no review"
    lines = [
        f"Verdict: {verdict.verdict} (confidence "
        f"{verdict.confidence:.2f}, {review})"
    ]

    if verdict.mitre_technique:
        lines.append(f"MITRE: {verdict.mitre_technique}")

    if verdict.owasp_category:
        lines.append(f"OWASP: {verdict.owasp_category}")

    lines.append(f"Summary: {verdict.summary}")

    return lines


def format_alert(
    case: dict[str, Any],
    verdict: AgentVerdict | None = None,
    incident_id: int | None = None,
) -> str:
    sensors = [clean(name, 40) for name in case["contributing_sensors"]]
    saved = incident_id if incident_id is not None else "not saved"
    lines = [
        f"Agithar alert: {clean(case['severity'], 10).upper()} severity",
        f"IP: {clean(case['ip'], 45)}",
        f"Case: {clean(case['case_id'], 80)}",
        f"Incident: {saved}",
        f"Composite score: {float(case['composite_score']):.2f} "
        f"({case['num_sensors']} sensors, "
        f"{case['num_strong_sensors']} strong)",
        f"Sensors: {', '.join(sensors[:MAX_SENSORS])}",
    ]
    lines.extend(verdict_lines(verdict))

    return defang("\n".join(lines))


def check_rate() -> None:
    now = time.monotonic()

    with _lock:
        while _sent_at and now - _sent_at[0] > RATE_WINDOW_SECONDS:
            _sent_at.popleft()

        if len(_sent_at) >= MAX_MESSAGES_PER_MINUTE:
            raise NotificationError("notification rate limit reached")

        _sent_at.append(now)


def retry_wait(response: httpx.Response, attempt: int) -> float:
    wait = RETRY_DELAY_SECONDS * (attempt + 1)

    if response.status_code == HTTP_TOO_MANY:
        try:
            wait = float(response.json()["parameters"]["retry_after"])
        except (ValueError, KeyError, TypeError):
            pass

    return min(wait, MAX_RETRY_WAIT_SECONDS)


def is_retryable(response: httpx.Response) -> bool:
    return (
        response.status_code == HTTP_TOO_MANY
        or response.status_code >= SERVER_ERROR_FLOOR
    )


async def post_message(url: str, 
                       payload: dict[str, Any]
                       ) -> httpx.Response:
    
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        return await client.post(url, json=payload)


async def deliver(url: str, 
                  payload: dict[str, Any]
                  ) -> httpx.Response:
    
    for attempt in range(MAX_ATTEMPTS):
        last = attempt == MAX_ATTEMPTS - 1

        try:
            response = await post_message(url, payload)
        except httpx.HTTPError as exc:
            # The url holds the bot token: never log or re-raise exc.
            logger.warning("telegram request failed: %s", type(exc).__name__)

            if last:
                raise NotificationError("telegram request failed") from None

            await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
            continue

        if not is_retryable(response) or last:
            return response

        await asyncio.sleep(retry_wait(response, attempt))

    raise NotificationError("telegram request failed")


def read_result(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        body = None

    if response.status_code != 200 or not isinstance(body, dict):
        logger.warning(
            "telegram rejected the message",
            extra={"status": response.status_code},
        )
        raise NotificationError("telegram rejected the message")

    if body.get("ok") is not True:
        raise NotificationError("telegram rejected the message")

    result = body.get("result")
    message_id = result.get("message_id") if isinstance(result, dict) else None

    return {"sent": True, "message_id": message_id}


async def send_message(text: str) -> dict[str, Any]:
    settings = get_settings()

    if settings.telegram_bot_token is None or not settings.telegram_chat_id:
        raise NotificationError("telegram is not configured")

    check_rate()
    safe_text = defang(
        sanitize_string(text, MAX_MESSAGE_CHARS, keep_newlines=True)
    )
    url = API_URL.format(token=settings.telegram_bot_token.get_secret_value())
    payload = {
        "chat_id": settings.telegram_chat_id,
        "text": safe_text,
        "disable_web_page_preview": True,
    }

    return read_result(await deliver(url, payload))


async def notify_admin(
    case: dict[str, Any],
    verdict: AgentVerdict | None = None,
    incident_id: int | None = None,
) -> dict[str, Any]:
    
    return await send_message(format_alert(case, 
                                           verdict, 
                                           incident_id
                                           ))
