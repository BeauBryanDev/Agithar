import asyncio
import time
from dataclasses import replace

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser
from app.core.config import get_settings
from app.core.logging import get_logger
from app.ingestion.log_tail import LogUnavailableError, load_window
from app.ingestion.traffic import recent_errors, series, summarize
from app.schemas.traffic import TrafficResponse

logger = get_logger("api.traffic")

router = APIRouter(tags=["traffic"])

MB = 1024 * 1024
CACHE_SECONDS = 5.0
RECENT_ERRORS = 15
LOG_MISSING = "The web server log is not available on this machine."

_cache: dict[int, tuple[float, TrafficResponse]] = {}
_lock = asyncio.Lock()


def compute(minutes: int) -> TrafficResponse:
    settings = get_settings()
    shop_map = settings.shop_map
    host_to_shop = {host: name for name, host in shop_map.items()}
    now = time.time()

    try:
        window = load_window(
            settings.nginx_log_path,
            set(shop_map.values()),
            now - minutes * 60,
            settings.chat_log_tail_mb * MB,
        )

    except LogUnavailableError:
        return TrafficResponse(
            available=False, 
            note=LOG_MISSING,
            window_minutes=minutes
        )

    shops = []

    for name, host in shop_map.items():
        mine = replace(
            window, lines=[l for l in window.lines if l.host == host]
        )
        summary = summarize(mine, minutes, host_to_shop)
        shops.append(
            {
                "name": name,
                "host": host,
                "series": series(mine.lines, minutes, now),
                **{
                    key: summary[key]
                    for key in (
                        "requests", "requests_per_minute", "error_rate",
                        "not_found_rate", "unique_clients", "status_classes",
                        "peak_minute", "top_paths", "top_error_paths",
                        "top_clients", "client_types",
                    )
                },
            }
        )

    overall = summarize(window, minutes, host_to_shop)

    return TrafficResponse(
        available=True,
        window_minutes=minutes,
        window_complete=overall["window_complete"],
        data_starts_at=overall["data_starts_at"],
        older_lines_not_read=overall["older_lines_not_read"],
        unreadable_lines={
            str(k): int(v) for k, v in overall["unreadable_lines"].items()
        },
        shops=shops,
        recent_errors=recent_errors(window,
                                    RECENT_ERRORS, 
                                    host_to_shop),
    )


@router.get("/traffic", response_model=TrafficResponse)
async def traffic(
    _user: CurrentUser,
    minutes: int = Query(60, ge=5, le=1440),
) -> TrafficResponse:
    # Per-shop traffic read from the newest part of the nginx log. Cached for
    # a few seconds so several open tabs read the file once.
    async with _lock:
        hit = _cache.get(minutes)

        if hit is not None and time.monotonic() - hit[0] < CACHE_SECONDS:
            return hit[1]

        try:
            value = await asyncio.to_thread(compute, minutes)

        except Exception as exc:
            logger.warning("traffic failed: %s", type(exc).__name__)
            value = TrafficResponse(
                available=False,
                note="Traffic could not be read.",
                window_minutes=minutes,
            )

        _cache[minutes] = (time.monotonic(), value)

        return value
