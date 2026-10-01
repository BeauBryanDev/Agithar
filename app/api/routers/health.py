from typing import Literal

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from app.core.logging import get_logger
from app.db.postgresql.session import get_session_factory


logger = get_logger("api.health")

router = APIRouter(prefix="/health", tags=["health"])


class LivenessResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Literal["ready", "degraded"]
    sensors: bool
    database: bool


def sensors_ready(request: Request) -> bool:
    registry = getattr(request.app.state, "registry", None)

    return registry is not None and registry.is_complete


def database_ready() -> bool:
    try:
        with get_session_factory()() as session:
            session.execute(text("SELECT 1"))
            
    except Exception as exc:
        logger.warning("database check failed: %s", type(exc).__name__)
        return False

    return True


@router.get("", response_model=LivenessResponse)
def liveness() -> LivenessResponse:
    return LivenessResponse(status="ok")


@router.get("/ready", response_model=ReadinessResponse)
def readiness(request: Request, 
              response: Response
              ) -> ReadinessResponse:
    sensors = sensors_ready(request)
    database = database_ready()
    is_ready = sensors and database

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessResponse(
        status="ready" if is_ready else "degraded",
        sensors=sensors,
        database=database,
    )
