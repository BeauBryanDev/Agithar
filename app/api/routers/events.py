import hmac
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.api.deps import CorrelatorDep, Registry
from app.core.auth import (
    InvalidTokenError,
    bearer_scheme,
    decode_access_token,
    unauthorized,
)
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.db.postgresql.users import User
from app.schemas.events import (
    EventBatchIn,
    EventBatchOut,
    EventResult,
    SensorEventIn,
)
from app.security.rate_limit import (
    FailureLimiter,
    UsageLimiter,
    client_ip,
    ensure_not_limited,
)
from app.services.event_service import (
    EventOutcome,
    EventRejectedError,
    ingest_event,
    timestamp_is_plausible,
)

logger = get_logger("api.events")

router = APIRouter(prefix="/events", tags=["events"])

BAD_KEY_MAX_FAILURES = 10
BAD_KEY_WINDOW_SECONDS = 900
EVENTS_WINDOW_SECONDS = 60
MAX_TRACKED_KEYS = 10000

REASON_SENSOR = "unknown sensor"
REASON_TIME = "timestamp out of range"
REASON_REJECTED = "event rejected"

bad_key_limiter = FailureLimiter(
    BAD_KEY_MAX_FAILURES, 
    BAD_KEY_WINDOW_SECONDS, 
    MAX_TRACKED_KEYS
)


@lru_cache
def events_limiter() -> UsageLimiter:
    return UsageLimiter(
        get_settings().events_rate_limit_per_minute, 
        EVENTS_WINDOW_SECONDS
    )


@dataclass(frozen=True)
class Principal:
    kind: str  # "key" or "admin"
    ident: str


def key_matches(supplied: str) -> bool:
    configured = get_settings().ingest_api_key

    if configured is None:
        return False

    return hmac.compare_digest(
        supplied.encode("utf-8"),
        configured.get_secret_value().encode("utf-8"),
    )


def admin_from_token(credentials: HTTPAuthorizationCredentials) -> Principal:
    try:
        data = decode_access_token(credentials.credentials)

    except InvalidTokenError:
        raise unauthorized() from None

    if data.user_id is None:
        raise unauthorized()

    try:
        session: Session = get_session_factory()()

    except DatabaseNotConfiguredError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        ) from None

    try:
        user = session.get(User, data.user_id)

    finally:
        session.close()

    if user is None or not user.is_active:
        raise unauthorized()

    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    return Principal("admin", str(user.user_id))


def event_writer(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme)
    ] = None,
    ingest_key: Annotated[str | None, Header(alias="X-Ingest-Key")] = None,
) -> Principal:
    # Who may push events: the ingest key (machine feeds) or an admin login.
    # Pushed events can raise cases, cost LLM money and send alerts, so this
    # is never open to ordinary users.
    if ingest_key is not None:
        ip = client_ip(request)
        ensure_not_limited(bad_key_limiter, ip)

        if not key_matches(ingest_key):
            bad_key_limiter.record_failure(ip)
            logger.warning("ingest key rejected")
            raise unauthorized()

        return Principal("key", "ingest-key")

    if credentials is None:
        raise unauthorized()

    return admin_from_token(credentials)


EventWriter = Annotated[Principal, Depends(event_writer)]


def check_rate(principal: Principal, count: int) -> None:
    limiter = events_limiter()

    for _ in range(count):
        wait = limiter.hit(principal.ident)

        if wait > 0:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many events, slow down",
                headers={"Retry-After": str(wait)},
            )


def pre_check(
    event: SensorEventIn, 
    known: set[str], now: float
) -> str | None:
    if event.source_sensor not in known:
        return REASON_SENSOR

    if not timestamp_is_plausible(event.timestamp, now):
        return REASON_TIME

    return None


def process(
    correlator: Any, events: list[SensorEventIn]
) -> list[EventOutcome | None]:
    # Worker thread: the database is synchronous. None means rejected.
    try:
        session = get_session_factory()()

    except DatabaseNotConfiguredError:
        session = None

    outcomes: list[EventOutcome | None] = []

    try:
        for event in events:
            try:
                outcomes.append(ingest_event(correlator, session, event))

            except EventRejectedError:
                outcomes.append(None)

    finally:
        if session is not None:
            session.close()

    return outcomes


async def handle(
    request: Request,
    principal: Principal,
    correlator: Any,
    registry: Any,
    events: list[SensorEventIn],
) -> list[EventResult]:
    check_rate(principal, len(events))
    now = time.time()
    known = set(registry.names)
    reasons = [pre_check(e, known, now) for e in events]
    valid = [e for e, why in zip(events, reasons) if why is None]
    outcomes = iter(await run_in_threadpool(process, correlator, valid))
    dispatcher = getattr(request.app.state, "dispatcher", None)
    settings = get_settings()
    results: list[EventResult] = []

    for why in reasons:
        if why is not None:
            results.append(EventResult(accepted=False, reason=why))
            continue

        outcome = next(outcomes)

        if outcome is None:
            results.append(EventResult(accepted=False, reason=REASON_REJECTED))
            continue

        # Log-only mode raises no case to the agent (no LLM cost, no alert);
        # the incident is still saved and shows in the feed as open.
        if (
            outcome.escalated
            and dispatcher is not None
            and not settings.ingestion_log_only
            and outcome.case is not None
        ):
            dispatcher.submit(outcome.case, outcome.incident_id)

        results.append(EventResult(accepted=True, escalated=outcome.escalated))

    logger.info(
        "events pushed",
        extra={
            "by": principal.kind,
            "count": len(events),
            "accepted": sum(r.accepted for r in results),
            "escalated": sum(r.escalated for r in results),
        },
    )

    return results

# HTTP ENDPOINTS

@router.post("", response_model=EventResult)
async def push_event(
    event: SensorEventIn,
    request: Request,
    principal: EventWriter,
    correlator: CorrelatorDep,
    registry: Registry,
) -> EventResult:
    (result,) = await handle(request, principal, 
                             correlator, registry, 
                             [event])

    if not result.accepted:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=result.reason or REASON_REJECTED,
        )

    return result


@router.post("/batch", response_model=EventBatchOut)
async def push_events(
    batch: EventBatchIn,
    request: Request,
    principal: EventWriter,
    correlator: CorrelatorDep,
    registry: Registry,
) -> EventBatchOut:
    results = await handle(
        request, principal, 
        correlator, registry,
        batch.events
    )
    accepted = sum(r.accepted for r in results)

    return EventBatchOut(
        accepted=accepted,
        rejected=len(results) - accepted,
        escalated=sum(r.escalated for r in results),
        results=results,
    )
