import ipaddress
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Query, status

from app.api.deps import CurrentUser, DbSession
from app.db.postgresql import repository
from app.schemas.incidents import (
    FeedItem,
    FeedList,
    IncidentList,
    IncidentRead,
)

MAX_CASE_KEY_CHARS = 80
DEFAULT_PAGE_SIZE = 50

router = APIRouter(prefix="/incidents", tags=["incidents"])

Skip = Annotated[int, Query(ge=0)]
Limit = Annotated[
    int, Query(ge=1, le=repository.MAX_PAGE_SIZE)
]
CaseKey = Annotated[
    str,
    Path(
        min_length=1,
        max_length=MAX_CASE_KEY_CHARS,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    ),
]


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid IP address",
        ) from exc



def build_list(
    result: tuple[list, int],
    skip: int, limit: int
) -> IncidentList:
    items, total = result

    return IncidentList(
        items=items, 
        total=total, 
        skip=skip,
        limit=limit
    )


@router.get("", response_model=FeedList)
def list_recent(
    _user: CurrentUser,
    db: DbSession,
    skip: Skip = 0,
    limit: Limit = DEFAULT_PAGE_SIZE,
    severity: Annotated[str | None, Query(max_length=10)] = None,
    status: Annotated[str | None, Query(max_length=20)] = None,
) -> FeedList:
    # The detection feed: newest incidents first, optional filters.
    try:
        items, total = repository.list_recent_incidents(
            db, severity, status, skip, limit
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail="Invalid severity or status"
        ) from exc

    return FeedList(
        items=[FeedItem.from_incident(item) for item in items],
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get("/by-ip/{ip}", response_model=IncidentList)
def list_by_ip(
    ip: str,
    _user: CurrentUser,
    db: DbSession,
    skip: Skip = 0,
    limit: Limit = DEFAULT_PAGE_SIZE,
) -> IncidentList:
    result = repository.list_incidents_by_ip(
        db, validate_ip(ip), skip, limit
    )

    return build_list(result, skip, limit)


@router.get("/by-severity/{severity}", response_model=IncidentList)
def list_by_severity(
    severity: str,
    _user: CurrentUser,
    db: DbSession,
    skip: Skip = 0,
    limit: Limit = DEFAULT_PAGE_SIZE,
) -> IncidentList:
    try:
        result = repository.list_incidents_by_severity(
            db, severity, skip, limit
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail="Invalid severity",
        ) from exc

    return build_list(result, skip, limit)


@router.get("/{case_key}", response_model=IncidentRead)
def get_incident(
    case_key: CaseKey, 
    _user: CurrentUser,
    db: DbSession
) -> IncidentRead:
    
    incident = repository.get_incident_by_case_key(db, case_key)

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident
