import asyncio
import time

from fastapi import APIRouter, Request

from app.api.deps import CurrentUser
from app.core.logging import get_logger
from app.schemas.telemetry import (
    DispatcherTelemetry,
    IngestionTelemetry,
    PipelineTelemetry,
    SensorTelemetry,
    ServerTelemetry,
    TelemetryResponse,
)
from app.services.os_service import get_server_snapshot

logger = get_logger("api.telemetry")

router = APIRouter(tags=["telemetry"])

# Several open tabs must not each cost a 1 s CPU sample.
CACHE_SECONDS = 3.0
_cache: tuple[float, ServerTelemetry | None] | None = None
_lock = asyncio.Lock()


async def read_server() -> ServerTelemetry | None:
    global _cache

    async with _lock:
        now = time.monotonic()

        if _cache is not None and now - _cache[0] < CACHE_SECONDS:
            return _cache[1]

        try:
            snap = await get_server_snapshot()
            value = ServerTelemetry(
                **snap["resources"],
                siblings=snap["siblings"],
                system=snap["system"],
            )

        except Exception as exc:
            logger.warning("server telemetry failed: %s", type(exc).__name__)
            value = None

        _cache = (now, value)

        return value


def read_ingestion(request: Request) -> IngestionTelemetry | None:
    feed = getattr(request.app.state, "ingestion", None)

    if feed is None:
        return None

    snap = feed.snapshot()

    return IngestionTelemetry(
        **{k: v for k, v in snap.items() if k != "enabled"}
    )


def read_pipeline(request: Request) -> PipelineTelemetry:
    state = request.app.state
    registry = getattr(state, "registry", None)
    correlator = getattr(state, "correlator", None)
    dispatcher = getattr(state, "dispatcher", None)

    sensors = SensorTelemetry(
        loaded=len(registry.sensors) if registry else 0,
        failed=len(registry.failures) if registry else 0,
        complete=bool(registry and registry.is_complete),
    )

    return PipelineTelemetry(
        ingestion=read_ingestion(request),
        correlator_windows=(
            correlator.stats()["open_windows"] if correlator else 0
        ),
        dispatcher=(
            DispatcherTelemetry(**dispatcher.stats()) if dispatcher else None
        ),
        sensors=sensors,
    )


@router.get("/telemetry", response_model=TelemetryResponse)
async def telemetry(
    _user: CurrentUser, request: Request
) -> TelemetryResponse:
    # Live numbers only: this machine, the pipeline and the agent queue.
    return TelemetryResponse(
        sampled_at=time.time(),
        server=await read_server(),
        pipeline=read_pipeline(request),
    )
