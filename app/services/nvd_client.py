import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass

import httpx
from pydantic import ValidationError

from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.vulnerabilities import VulnerabilityRead
from app.services.nvd_parse import parse_nvd

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
RATE_WINDOW_SECONDS = 30.0
# Conservative limits, a little under what NVD documents (from memory,
# not verified): about 5 requests per 30 s without a key, 50 with a key.
MAX_REQUESTS_PUBLIC = 4
MAX_REQUESTS_KEYED = 40
CACHE_TTL_SECONDS = 3600.0
CACHE_MAX_ENTRIES = 256
HTTP_FORBIDDEN = 403
HTTP_TOO_MANY = 429

STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_RATE_LIMITED = "rate_limited"
STATUS_UNAVAILABLE = "unavailable"


logger = get_logger("services.nvd")

_sent_at: deque[float] = deque()
_cache: OrderedDict[str, tuple[float, VulnerabilityRead]] = OrderedDict()
_lock = threading.Lock()


@dataclass(frozen=True)
class LiveResult:
    status: str
    vulnerability: VulnerabilityRead | None = None
    from_cache: bool = False


def allowed_requests() -> int:
    keyed = get_settings().nvd_api_key is not None

    return MAX_REQUESTS_KEYED if keyed else MAX_REQUESTS_PUBLIC


def take_rate_slot() -> bool:
    now = time.monotonic()

    with _lock:
        while _sent_at and now - _sent_at[0] > RATE_WINDOW_SECONDS:
            _sent_at.popleft()

        if len(_sent_at) >= allowed_requests():
            return False

        _sent_at.append(now)

    return True


def cache_get(cve_id: str) -> VulnerabilityRead | None:
    with _lock:
        entry = _cache.get(cve_id)

        if entry is None:
            return None

        stored_at, vulnerability = entry

        if time.monotonic() - stored_at > CACHE_TTL_SECONDS:
            del _cache[cve_id]
            return None

        return vulnerability


def cache_put(cve_id: str, vulnerability: VulnerabilityRead) -> None:
    with _lock:
        _cache[cve_id] = (time.monotonic(), vulnerability)
        _cache.move_to_end(cve_id)

        while len(_cache) > CACHE_MAX_ENTRIES:
            _cache.popitem(last=False)


async def request_nvd(cve_id: str) -> httpx.Response:
    headers = {"Accept": "application/json"}
    key = get_settings().nvd_api_key

    if key is not None:
        headers["apiKey"] = key.get_secret_value()

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        return await client.get(
            NVD_URL, params={"cveId": cve_id}, headers=headers
        )


def read_response(response: httpx.Response, cve_id: str) -> LiveResult:
    if response.status_code in (HTTP_FORBIDDEN, HTTP_TOO_MANY):
        return LiveResult(STATUS_RATE_LIMITED)

    if response.status_code == 404:
        return LiveResult(STATUS_NOT_FOUND)

    too_large = len(response.content) > MAX_RESPONSE_BYTES

    if response.status_code != 200 or too_large:
        return LiveResult(STATUS_UNAVAILABLE)

    try:
        body = response.json()
        
    except ValueError:
        return LiveResult(STATUS_UNAVAILABLE)

    if isinstance(body, dict) and body.get("totalResults") == 0:
        return LiveResult(STATUS_NOT_FOUND)

    try:
        vulnerability = parse_nvd(body, cve_id)
        
    except (ValidationError, AttributeError, TypeError):
        return LiveResult(STATUS_UNAVAILABLE)

    if vulnerability is None:
        return LiveResult(STATUS_UNAVAILABLE)

    return LiveResult(STATUS_OK, vulnerability)


async def fetch_live(cve_id: str) -> LiveResult:
    cached = cache_get(cve_id)

    if cached is not None:
        return LiveResult(STATUS_OK, cached, from_cache=True)

    if not take_rate_slot():
        return LiveResult(STATUS_RATE_LIMITED)

    try:
        response = await request_nvd(cve_id)
    except httpx.HTTPError as exc:
        logger.warning("nvd request failed: %s", type(exc).__name__)

        return LiveResult(STATUS_UNAVAILABLE)

    result = read_response(response, cve_id)

    if result.vulnerability is not None:
        cache_put(cve_id, result.vulnerability)

    return result
