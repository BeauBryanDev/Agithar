from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import CurrentUser, DbSession
from app.db.postgresql import repository
from app.schemas.dashboard import DashboardData
from app.services import dashboard_service

DEFAULT_HOURS = 24
MAX_HOURS = 720

router = APIRouter(tags=["dashboard"])

Hours = Annotated[int, Query(ge=1, le=MAX_HOURS)]


@router.get("/dashboard", response_model=DashboardData)
def dashboard(
    _user: CurrentUser, 
    db: DbSession, 
    hours: Hours = DEFAULT_HOURS
) -> DashboardData:
    now = datetime.now(timezone.utc)
    rows = repository.incidents_since(db, now - timedelta(hours=hours))
    truncated = len(rows) >= repository.MAX_DASHBOARD_ROWS

    return dashboard_service.build_dashboard(rows, now, hours, truncated)
