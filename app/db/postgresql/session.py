from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


POOL_SIZE = 5
MAX_OVERFLOW = 10
POOL_RECYCLE_SECONDS = 1800


class DatabaseNotConfiguredError(Exception):
    pass


@lru_cache
def get_engine() -> Engine:
    url = get_settings().database_url

    if url is None:
        raise DatabaseNotConfiguredError("DATABASE_URL is not configured")

    return create_engine(
        url.get_secret_value(),
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_recycle=POOL_RECYCLE_SECONDS,
        pool_pre_ping=True,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_engine(), autoflush=False, expire_on_commit=False
    )
