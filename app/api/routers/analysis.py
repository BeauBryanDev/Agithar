from fastapi import APIRouter, HTTPException, status

from app.api.deps import CurrentUser, Registry
from app.core.logging import get_logger
from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse
from app.services import analysis_service

logger = get_logger("api.analysis")

router = APIRouter(tags=["analysis"])


@router.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    request: AnalyzeRequest, 
    user: CurrentUser, 
    registry: Registry
) -> AnalyzeResponse:
    # A plain def: the sensors are CPU work, so FastAPI runs it in its
    # thread pool and the event loop stays free. session_id is not used
    # here: chat sessions belong to /chat.
    try:
        return analysis_service.analyze(registry, request)

    except ValueError:
        logger.info("input not analyzable", 
                    extra={"user_id": user.user_id})

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No sensor could analyze this input",
        ) from None
