from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from app.api.deps import CurrentUser
from app.schemas.coverage import CoverageResponse
from app.services import coverage_service

LAYER_FILENAME = "agithar_coverage_layer.json"
UNAVAILABLE = "Coverage data is unavailable"

router = APIRouter(tags=["coverage"])


@router.get("/coverage", response_model=CoverageResponse)
def coverage(_user: CurrentUser) -> CoverageResponse:
    try:
        return CoverageResponse(**coverage_service.get_coverage())

    except coverage_service.CoverageError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, UNAVAILABLE
        ) from None


@router.get("/coverage/navigator")
def navigator(_user: CurrentUser) -> JSONResponse:
    # A layer file for the ATT&CK Navigator, offered as a download.
    try:
        layer = coverage_service.navigator_layer()

    except coverage_service.CoverageError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, UNAVAILABLE
        ) from None

    disposition = f'attachment; filename="{LAYER_FILENAME}"'

    return JSONResponse(layer, headers={"Content-Disposition": disposition})
