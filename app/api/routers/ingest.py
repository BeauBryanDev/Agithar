import asyncio
from functools import lru_cache
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.api.deps import CurrentUser, Registry
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingestion.upload import UploadRejected, check_extension, safe_name
from app.schemas.ingests import IngestResult
from app.security.rate_limit import UsageLimiter
from app.services.ingest_service import analyze_upload

logger = get_logger("api.ingest")

router = APIRouter(tags=["ingest"])    

WINDOW_SECONDS = 600
READ_CHUNK = 65536
GRACE_SECONDS = 20

# One analysis at a time: it is CPU work and the box is shared.
_busy = asyncio.Semaphore(1)


@lru_cache
def ingest_limiter() -> UsageLimiter:
    return UsageLimiter(
        get_settings().ingest_rate_limit_per_10min,
        WINDOW_SECONDS
    )


def reject(code: int,
           detail: str,
           headers: dict | None = None):
    return HTTPException(status_code=code, 
                         detail=detail,
                         headers=headers)


async def read_capped(request: Request,
                      cap: int) -> bytes:
    # The body is read in chunks and the read stops the moment the cap is
    # passed, so an oversized or endless upload never fills memory. Nothing
    # is written to disk.
    declared = request.headers.get("content-length")

    if declared is not None:
        if not declared.isdigit():
            raise reject(status.HTTP_400_BAD_REQUEST, 
                         "Bad content length")

        if int(declared) > cap:
            raise reject(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "The file is larger than the limit.",
            )

    data = bytearray()

    async for chunk in request.stream():
        data += chunk

        if len(data) > cap:
            raise reject(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "The file is larger than the limit.",
            )

    return bytes(data)


@router.post("/ingest", response_model=IngestResult)
async def ingest(
    request: Request,
    user: CurrentUser,
    registry: Registry,
    filename: Annotated[str, Query(min_length=1, max_length=255)],
) -> IngestResult:
    # The body is the raw file (not multipart): no temporary file is ever
    # created. The file is analysed by the sensors only; it is never
    # executed, unpacked or stored, and no LLM is involved.
    settings = get_settings()
    name = safe_name(filename)

    try:
        check_extension(name)

    except UploadRejected as exc:
        raise reject(exc.status, exc.reason) from None

    wait = ingest_limiter().hit(str(user.user_id))

    if wait > 0:
        raise reject(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many uploads. Try again later.",
            {"Retry-After": str(wait)},
        )

    data = await read_capped(request, settings.ingest_max_bytes)

    if _busy.locked():
        raise reject(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Another analysis is running. Try again in a moment.",
            {"Retry-After": "10"},
        )

    async with _busy:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    analyze_upload,
                    registry,
                    name,
                    data,
                    max_lines=settings.ingest_max_lines,
                    max_flow_rows=settings.ingest_max_flow_rows,
                    budget_seconds=settings.ingest_time_budget_seconds,
                ),
                timeout=settings.ingest_time_budget_seconds + GRACE_SECONDS,
            )

        except UploadRejected as exc:
            raise reject(exc.status, exc.reason) from None

        except asyncio.TimeoutError:
            logger.warning("upload analysis timed out")
            raise reject(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "The analysis took too long.",
            ) from None

        except Exception as exc:
            logger.error("upload analysis failed: %s", type(exc).__name__)
            raise reject(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "The file could not be analysed.",
            ) from None
