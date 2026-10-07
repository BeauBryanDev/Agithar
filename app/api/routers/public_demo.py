import asyncio
import time
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.agent.public_limits import live_nvd_allowed
from app.api.deps import CurrentGuest, Registry
from app.api.routers.ingest import read_capped, reject
from app.api.routers.public import ensure_enabled, limited
from app.api.routers.vulnerabilities import CVE_ID, MAX_QUERY_CHARS, NOT_A_CVE
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingestion.upload import UploadRejected, check_extension, safe_name
from app.schemas.ingests import IngestResult
from app.schemas.sensors import SensorsResponse
from app.schemas.vulnerabilities import VulnSearchResponse
from app.security.client_ip import Visitor, identify
from app.security.rate_limit import UsageLimiter
from app.services import cve_service
from app.services.ingest_service import analyze_upload
from app.services.sensor_service import overview
from app.services.vulnerability_view import to_record

logger = get_logger("api.public_demo")

# The read-only tools of the public demo: sensors, CVE lookup, file analysis.
# Every route needs a guest token AND counts against the real visitor (by
# IP), so a new token never means a new allowance. None of them reads shop
# data, incidents, the live feed or anything of the deployment.
router = APIRouter(prefix="/public", tags=["public"])

WINDOW_SECONDS = 600
HOUR_SECONDS = 3600
GRACE_SECONDS = 10
SENSORS_CACHE_SECONDS = 30.0
GLOBAL_KEY = "public"
DEMO_FED_BY = "the demo runs it on text or files that you provide"


@lru_cache
def sensors_limiter() -> UsageLimiter:
    return UsageLimiter(get_settings().public_sensors_per_10min, WINDOW_SECONDS)


@lru_cache
def vuln_limiter() -> UsageLimiter:
    return UsageLimiter(get_settings().public_vuln_per_10min, WINDOW_SECONDS)


@lru_cache
def ingest_limiter() -> UsageLimiter:
    return UsageLimiter(get_settings().public_ingest_per_10min, WINDOW_SECONDS)


@lru_cache
def ingest_global_budget() -> UsageLimiter:
    return UsageLimiter(
        get_settings().public_ingest_per_hour_global, HOUR_SECONDS
    )


def spend(limiter: UsageLimiter, visitor: Visitor) -> None:
    wait = limiter.hit(visitor.key)

    if wait > 0:
        raise limited("Too many requests. Try again later.", wait)


# sensors (read only) /WE do not want to expose the live feed numbers/
# /WE do not want to expose the flagged events (real IPs and paths)/
# /WE do not want to expose the error text/
_sensors_cache: tuple[float, SensorsResponse] | None = None
_sensors_lock = asyncio.Lock()


def public_view(data: dict) -> SensorsResponse:
    # The operators' view minus everything about the deployment: no live
    # feed numbers, no flagged events (real IPs and paths), no error text.
    sensors = []

    for item in data["sensors"]:
        sensors.append(
            {
                **item,
                "error": None,
                "fed_by": DEMO_FED_BY,
                "activity": {
                    "scored": None,
                    "flagged": None,
                    "flagged_last_hour": 0,
                    "last_flagged_at": None,
                    "recent": [],
                },
            }
        )

    return SensorsResponse(**{**data, 
                              "feed_running": False,
                              "sensors": sensors}
                           )


@router.get("/sensors", response_model=SensorsResponse)
async def public_sensors(
    request: Request, _guest: CurrentGuest, registry: Registry
) -> SensorsResponse:
    global _sensors_cache

    ensure_enabled()
    spend(sensors_limiter(), identify(request))

    # One probe of the five models at most every 30 s for ALL visitors.
    async with _sensors_lock:
        now = time.monotonic()

        if (
            _sensors_cache is not None
            and now - _sensors_cache[0] < SENSORS_CACHE_SECONDS
        ):
            return _sensors_cache[1]

        data = await asyncio.to_thread(overview, registry, None)
        value = public_view(data)
        _sensors_cache = (now, value)

        return value


#  CVE lookup 


@router.get("/vuln/search", response_model=VulnSearchResponse)
async def public_vuln(
    request: Request,
    _guest: CurrentGuest,
    q: Annotated[str, Query(max_length=MAX_QUERY_CHARS)] = "",
) -> VulnSearchResponse:
    ensure_enabled()
    text = q.strip()

    if not CVE_ID.match(text):
        return VulnSearchResponse(results=[], note=NOT_A_CVE)

    spend(vuln_limiter(), identify(request))

    # The live NVD API is shared by all visitors: when its hourly budget is
    # used up the local dataset answers alone.
    live = "auto" if live_nvd_allowed() else "never"

    try:
        result = await cve_service.lookup_cve(text, live=live)

    except cve_service.CveLookupError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "CVE lookup is unavailable"
        ) from None

    if not result.found or result.vulnerability is None:
        return VulnSearchResponse(results=[], note=result.note)

    record = to_record(result.vulnerability, result.source)

    return VulnSearchResponse(results=[record], note=result.note)


# file analysis 

_ingest_slot = asyncio.Semaphore(1)


@router.post("/ingest", response_model=IngestResult)
async def public_ingest(
    request: Request,
    _guest: CurrentGuest,
    registry: Registry,
    filename: Annotated[str, Query(min_length=1, max_length=255)],
) -> IngestResult:
    # Same analysis as the operators' upload (raw body, nothing stored, no
    # LLM) with much smaller caps and a per-visitor and global budget.
    ensure_enabled()
    settings = get_settings()
    visitor = identify(request)
    name = safe_name(filename)

    try:
        check_extension(name)

    except UploadRejected as exc:
        raise reject(exc.status, exc.reason) from None

    declared = request.headers.get("content-length")

    # A visitor's upload is refused early when it is clearly too large.
    if declared is not None and declared.isdigit():
        if int(declared) > settings.public_ingest_max_bytes:
            raise reject(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "The demo accepts files up to "
                f"{settings.public_ingest_max_bytes // 1024} KB.",
            )

    spend(ingest_limiter(), visitor)

    if ingest_global_budget().hit(GLOBAL_KEY) > 0:
        raise reject(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "The demo has reached its file analysis limit for this hour.",
            {"Retry-After": "300"},
        )

    data = await read_capped(request, settings.public_ingest_max_bytes)

    if _ingest_slot.locked():
        raise reject(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Another analysis is running. Try again in a moment.",
            {"Retry-After": "10"},
        )

    async with _ingest_slot:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    analyze_upload,
                    registry,
                    name,
                    data,
                    max_lines=settings.public_ingest_max_lines,
                    max_flow_rows=settings.public_ingest_max_flow_rows,
                    budget_seconds=settings.public_ingest_time_budget_seconds,
                ),
                timeout=settings.public_ingest_time_budget_seconds
                + GRACE_SECONDS,
            )

        except UploadRejected as exc:
            raise reject(exc.status, exc.reason) from None

        except asyncio.TimeoutError:
            raise reject(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "The analysis took too long.",
            ) from None

        except Exception as exc:
            logger.error("public analysis failed: %s", type(exc).__name__)
            raise reject(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "The file could not be analysed.",
            ) from None
