import asyncio
import time

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser, Registry
from app.schemas.sensors import SensorsResponse
from app.services.sensor_service import overview

router = APIRouter(tags=["sensors"])

# The probes run five models: do not repeat them for every open tab.
CACHE_SECONDS = 10.0
_cache: tuple[float, SensorsResponse] | None = None
_lock = asyncio.Lock()


@router.get("/sensors", response_model=SensorsResponse)
async def sensors(
    _user: CurrentUser,
    registry: Registry, 
    request: Request
) -> SensorsResponse:
    global _cache

    async with _lock:
        now = time.monotonic()

        if _cache is not None and now - _cache[0] < CACHE_SECONDS:
            return _cache[1]

        feed = getattr(request.app.state, "ingestion", None)
        data = await asyncio.to_thread(overview, registry, feed)
        value = SensorsResponse(**data)
        _cache = (now, value)

        return value
