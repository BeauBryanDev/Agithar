import asyncio
import time

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.agent.tools.shops import ShopName, hosts_for, shop_of_host
from app.core.config import get_settings
from app.ingestion.log_tail import load_window
from app.ingestion.traffic import recent_errors

NAME = "shop_recent_errors"
MB = 1024 * 1024
MAX_LIMIT = 25


class ErrorsArgs(BaseModel):
    shop: ShopName
    minutes: int = Field(default=60, ge=5, le=1440)
    limit: int = Field(default=15, ge=1, le=MAX_LIMIT)

    model_config = ConfigDict(extra="forbid")


def compute(shop: str, minutes: int, limit: int) -> dict:
    settings = get_settings()
    window = load_window(
        settings.nginx_log_path,
        hosts_for(shop),
        time.time() - minutes * 60,
        settings.chat_log_tail_mb * MB,
    )

    return {
        "shop": shop,
        "window_minutes": minutes,
        "window_complete": window.complete,
        "errors": recent_errors(window, limit, shop_of_host()),
    }


async def run(shop: str, minutes: int = 60, limit: int = 15) -> str:
    work = asyncio.to_thread(compute, shop, minutes, limit)

    return await guarded(NAME, work)


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "The latest failed requests (status 400 and above) of one shop, "
        "newest first: time, client IP, method, path without query string, "
        "status and client type. Use it to see what a scanner or a broken "
        "link is hitting."
    ),
    args_schema=ErrorsArgs,
)
