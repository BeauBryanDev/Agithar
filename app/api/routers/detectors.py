from fastapi import APIRouter

from app.api.deps import CurrentUser, Registry
from app.schemas.detectors import DetectorInfo, DetectorsResponse

router = APIRouter(tags=["detectors"])


@router.get("/detectors", response_model=DetectorsResponse)
def detectors(_user: CurrentUser, 
              registry: Registry
              ) -> DetectorsResponse:
    # Which sensors are running and at what threshold. A sensor that failed
    # to load is listed by its class name only: the error text stays in the
    # server log.
    loaded = [
        DetectorInfo(
            name=name,
            status="loaded",
            model=str(sensor.metadata.get("model") or "") or None,
            threshold=getattr(sensor, "threshold", None),
        )
        for name, sensor in sorted(registry.sensors.items())
    ]
    failed = [
        DetectorInfo(name=name, status="failed")
        for name in sorted(registry.failures)
    ]

    return DetectorsResponse(
        detectors=loaded + failed, 
        complete=registry.is_complete
    )
