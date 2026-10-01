from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routers import health, users
from app.core.config import get_settings
from app.core.lifespan import lifespan
from app.core.logging import get_logger


logger = get_logger("main")

APP_TITLE = "Aegis Cyber Guard"
APP_VERSION = "0.1.0"
API_PREFIX = "/api"
ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
ALLOWED_HEADERS = ["Authorization", "Content-Type"]
CORS_MAX_AGE = 600
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

# TODO: add the other routers once they define `router`.
ROUTERS: tuple[APIRouter, ...] = (
    health.router,
    users.router,
)


async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)

    return response


async def handle_unexpected_error(
    request: Request, exc: Exception
) -> JSONResponse:
    logger.error(
        "unhandled error on %s %s: %s",
        request.method,
        request.url.path,
        type(exc).__name__,
    )

    return JSONResponse(
        status_code=500, content={"detail": "Internal server error"}
    )


def add_middleware(app: FastAPI) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_origin_list,
        allow_credentials=False,
        allow_methods=ALLOWED_METHODS,
        allow_headers=ALLOWED_HEADERS,
        max_age=CORS_MAX_AGE,
    )
    app.middleware("http")(add_security_headers)


def create_app() -> FastAPI:
    app = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        lifespan=lifespan,
    )

    add_middleware(app)
    app.add_exception_handler(Exception, handle_unexpected_error)

    for router in ROUTERS:
        app.include_router(router, prefix=API_PREFIX)

    return app


app = create_app()
