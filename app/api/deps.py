from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_token_data, unauthorized
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.correlator.correlator import Correlator
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.db.postgresql.users import User
from app.schemas.users import TokenData
from app.sensors.registry import SensorRegistry


logger = get_logger("api.deps")


def service_unavailable(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, 
        detail=detail
    )


def get_db() -> Iterator[Session]:
    try:
        session = get_session_factory()()
        
    except DatabaseNotConfiguredError:
        logger.error("database is not configured")
        raise service_unavailable("Database is unavailable")

    try:
        yield session
        
    finally:
        session.close()


def get_registry(request: Request) -> SensorRegistry:
    
    registry = getattr(request.app.state, "registry", None)

    if registry is None:
        raise service_unavailable("Sensors are unavailable")

    return registry


def get_correlator(request: Request) -> Correlator:
    correlator = getattr(request.app.state, "correlator", None)

    if correlator is None:
        raise service_unavailable("Correlator is unavailable")

    return correlator


def get_current_user(
    token_data: Annotated[TokenData, Depends(get_current_token_data)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if token_data.user_id is None:
        raise unauthorized()

    user = db.get(User, token_data.user_id)

    # deleted or disabled users lose access even with a valid token
    if user is None or not user.is_active:
        raise unauthorized()

    return user


def require_admin(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    if not user.is_admin:
        logger.warning("admin access denied", 
                       extra={"user_id": user.user_id}
                       )
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )

    return user


DbSession = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentAdmin = Annotated[User, Depends(require_admin)]
AppSettings = Annotated[Settings, Depends(get_settings)]
Registry = Annotated[SensorRegistry, Depends(get_registry)]
CorrelatorDep = Annotated[Correlator, Depends(get_correlator)]
