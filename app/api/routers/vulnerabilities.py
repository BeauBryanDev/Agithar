import re
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import CurrentUser
from app.core.logging import get_logger
from app.schemas.vulnerabilities import VulnSearchResponse
from app.services import cve_service
from app.services.vulnerability_view import to_record

logger = get_logger("api.vuln")

MAX_QUERY_CHARS = 64
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$", re.IGNORECASE)
NOT_A_CVE = (
    "Enter a CVE ID such as CVE-2021-44228. Searching by product or "
    "description is not available."
)

router = APIRouter(prefix="/vuln", tags=["vulnerabilities"])


@router.get("/search", response_model=VulnSearchResponse)
async def search(
    user: CurrentUser,
    q: Annotated[str, Query(max_length=MAX_QUERY_CHARS)] = "",
) -> VulnSearchResponse:
    text = q.strip()

    # Only an exact CVE id is looked up: the local dataset and the live NVD
    # API are keyed by id, there is no text index on purpose (RAM).
    if not CVE_ID.match(text):
        return VulnSearchResponse(results=[], note=NOT_A_CVE)

    try:
        result = await cve_service.lookup_cve(text)

    except cve_service.CveLookupError:
        logger.warning("cve lookup failed", extra={"user_id": user.user_id})

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CVE lookup is unavailable",
        ) from None

    if not result.found or result.vulnerability is None:
        return VulnSearchResponse(results=[], note=result.note)

    record = to_record(result.vulnerability, result.source)

    return VulnSearchResponse(results=[record], note=result.note)
