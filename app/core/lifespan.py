import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.agent.dispatcher import get_dispatcher
from app.agent.recovery import recover_open_cases
from app.agent.tools import analyze_input
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


async def recover(settings: Settings) -> None:
    # Recovery must never stop the server from starting.
    if not settings.recover_on_startup:
        logger.info("startup recovery is disabled")
        return

    try:
        count = await recover_open_cases(get_dispatcher())

    except Exception as exc:
        logger.error("startup recovery failed: %s", type(exc).__name__)
        return

    logger.info("startup recovery: %d open cases resubmitted", count)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    check_security_settings(settings)

    app.state.settings = settings
    app.state.registry = await load_sensors()
    app.state.correlator = Correlator()
    analyze_input.set_registry(app.state.registry)
    app.state.dispatcher = get_dispatcher()
    await recover(settings)
    logger.info("startup complete: sensors=%s", 
                app.state.registry.names
                )

    try:
        yield
        
    finally:
        await app.state.dispatcher.shutdown()
        analyze_input.set_registry(None)
        app.state.dispatcher = None
        app.state.correlator = None
        app.state.registry = None
        logger.info("shutdown complete")
