import time

from fastapi import APIRouter, Query, Request

from app.api.deps import CurrentUser
from app.utils.live_stats import WINDOW_MINUTES
from app.schemas.live import LiveResponse

router = APIRouter(tags=["live"])


@router.get("/live", response_model=LiveResponse)
def live(
    _user: CurrentUser,
    request: Request,
    limit: int = Query(100, ge=1, le=200),
) -> LiveResponse:
    # What the log feed saw most recently, from memory. Empty (enabled false)
    # when ingestion is off.
    feed = getattr(request.app.state, "ingestion", None)

    if feed is None:
        return LiveResponse(
            enabled=False,
            log_only=True,
            events=[],
            per_minute=[],
            top_ips=[],
            top_paths=[],
            anomalies_in_window=0,
            window_minutes=WINDOW_MINUTES,
        )

    return LiveResponse(
        enabled=True,
        log_only=feed.log_only,
        **feed.live.snapshot(time.time(), feed=limit),
    )
