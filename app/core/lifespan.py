import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.correlator.correlator import Correlator
from app.sensors.registry import SensorRegistry, load_default_registry


logger = get_logger("core.lifespan")


def check_security_settings(settings: Settings) -> None:
    if settings.jwt_secret_key is None:
        raise RuntimeError("JWT_SECRET_KEY is not configured")


async def load_sensors() -> SensorRegistry:
    # model loading blocks, so keep it off the event loop
    registry = await asyncio.to_thread(load_default_registry)

    if not registry.names:
        raise RuntimeError("no sensor could be loaded")

    if not registry.is_complete:
        logger.warning(
            "running with failed sensors: %s", 
            sorted(registry.failures)
        )

    return registry


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    check_security_settings(settings)

    app.state.settings = settings
    app.state.registry = await load_sensors()
    app.state.correlator = Correlator()
    logger.info("startup complete: sensors=%s", 
                app.state.registry.names
                )

    try:
        yield
        
    finally:
        app.state.correlator = None
        app.state.registry = None
        logger.info("shutdown complete")
