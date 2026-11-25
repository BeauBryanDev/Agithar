
import asyncio
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.utils.network import normalize_ip

logger = get_logger("services.greynoise")

BASE_URL = "https://api.greynoise.io/v3/community"
REQUEST_TIMEOUT_SECONDS = 8
CACHE_TTL_SECONDS = 3 * 24 * 3600
MAX_CACHE_ENTRIES = 256
WEEK_SECONDS = 7 * 24 * 3600
WEEKLY_BUDGET = 40
COOLDOWN_AFTER_429_SECONDS = 3600
MAX_NAME_CHARS = 128
CLASSES = {"benign", "malicious", "unknown"}
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_budget: dict[str, Any] | None = None
_lock = asyncio.Lock()


def empty_budget() -> dict[str, Any]:
    return {
        "calls": [],
        "blocked_until": 0.0,
    }


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_budget(path: Path) -> dict[str, Any]:
    # A missing or corrupt file starts a fresh week; a 429 still stops us.
    try:
        data = json.loads(path.read_text(encoding="utf-8"))

    except FileNotFoundError:
        return empty_budget()

    except (OSError, ValueError):
        logger.warning("greynoise budget file unreadable, starting fresh")
        return empty_budget()

    if not isinstance(data, dict) or not isinstance(data.get("calls"), list):
        logger.warning("greynoise budget file invalid, starting fresh")
        return empty_budget()

    blocked = data.get("blocked_until")

    return {
        "calls": [float(c) for c in data["calls"] if is_number(c)],
        "blocked_until": float(blocked) if is_number(blocked) else 0.0,
    }


def save_budget(path: Path, budget: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=path.parent)

        with os.fdopen(fd, "w") as handle:
            json.dump(budget, handle)

        os.chmod(name, 0o600)
        os.replace(name, path)

    except OSError as exc:
        logger.warning("greynoise budget not saved: %s", type(exc).__name__)


def current_budget(now: float) -> dict[str, Any]:
    global _budget

    if _budget is None:
        _budget = load_budget(get_settings().grey_noise_budget_path)

    _budget["calls"] = [c for c in _budget["calls"] if now - c < WEEK_SECONDS]

    return _budget


async def reserve_call(now: float) -> bool:
    # Counted before the request, so a failed call still uses budget.
    async with _lock:
        budget = current_budget(now)

        if now < budget["blocked_until"]:
            return False

        if len(budget["calls"]) >= WEEKLY_BUDGET:
            return False

        budget["calls"].append(now)
        save_budget(get_settings().grey_noise_budget_path, budget)

        return True


async def pause_lookups(now: float) -> None:
    async with _lock:
        budget = current_budget(now)
        budget["blocked_until"] = now + COOLDOWN_AFTER_429_SECONDS
        save_budget(get_settings().grey_noise_budget_path, budget)


def remember(ip: str, now: float, result: dict[str, Any]) -> None:
    if len(_cache) >= MAX_CACHE_ENTRIES:
        oldest = None

        for key, (expires, _) in _cache.items():
            if oldest is None or expires < _cache[oldest][0]:
                oldest = key

        del _cache[oldest]

    _cache[ip] = (now + CACHE_TTL_SECONDS, result)


def clean_result(data: dict[str, Any]) -> dict[str, Any]:
    classification = data.get("classification")
    name = data.get("name")
    last_seen = data.get("last_seen")

    if isinstance(name, str):
        name = sanitize_string(name, MAX_NAME_CHARS)[:MAX_NAME_CHARS] or None
    else:
        name = None

    if not isinstance(last_seen, str) or not DATE_PATTERN.match(last_seen):
        last_seen = None

    return {
        "noise": data.get("noise") is True,
        "riot": data.get("riot") is True,
        "classification": classification if classification in CLASSES else None,
        "name": name,
        "last_seen": last_seen,
    }


async def lookup_ip(ip: str) -> dict[str, Any] | None:
    # None means no answer (no key, no budget, error); it never raises.
    settings = get_settings()

    if settings.grey_noise_api_key is None:
        return None

    try:
        ip = normalize_ip(ip)
    except ValueError:
        return None

    now = time.time()
    cached = _cache.get(ip)

    if cached is not None and cached[0] > now:
        return cached[1]

    if not await reserve_call(now):
        return None

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            response = await client.get(
                f"{BASE_URL}/{ip}",
                headers={
                    "key": settings.grey_noise_api_key.get_secret_value(),
                    "Accept": "application/json",
                },
            )

    except httpx.HTTPError as exc:
        logger.warning("greynoise lookup failed: %s", type(exc).__name__)
        return None

    if response.status_code == 429:
        await pause_lookups(now)
        logger.warning("greynoise rate limited, pausing lookups")
        return None

    # 404 means the IP was not seen scanning and is not in RIOT: an answer.
    if response.status_code not in (200, 404):
        logger.warning("greynoise returned status %s", response.status_code)
        return None

    try:
        data = response.json()
    except ValueError:
        logger.warning("greynoise returned an invalid body")
        return None

    if not isinstance(data, dict):
        logger.warning("greynoise returned an invalid body")
        return None

    result = clean_result(data)
    remember(ip, now, result)

    return result
