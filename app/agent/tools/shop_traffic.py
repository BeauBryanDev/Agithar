import asyncio
import time

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field

from app.agent.tools.common import guarded
from app.agent.tools.shops import ShopName, hosts_for, shop_of_host
from app.core.config import get_settings
from app.ingestion.log_tail import load_window
from app.ingestion.traffic import summarize

NAME = "shop_traffic"
MB = 1024 * 1024


class TrafficArgs(BaseModel):
    shop: ShopName
    minutes: int = Field(default=60, ge=5, le=1440,
                         description="How far back to look, in minutes")

    model_config = ConfigDict(extra="forbid")


def compute(shop: str, minutes: int) -> dict:
    settings = get_settings()
    since = time.time() - minutes * 60
    window = load_window(
        settings.nginx_log_path,
        hosts_for(shop),
        since,
        settings.chat_log_tail_mb * MB,
    )

    return {"shop": shop, **summarize(window, minutes, shop_of_host())}


async def run(shop: str, minutes: int = 60) -> str:
    return await guarded(NAME, asyncio.to_thread(compute, shop, minutes))


TOOL = StructuredTool.from_function(
    coroutine=run,
    name=NAME,
    description=(
        "Live traffic of one shop (or all) from the web server log: request "
        "counts and rate, status classes, error and 404 rates, busiest "
        "minute, top paths (query strings removed), top client IPs, and "
        "client types (browsers, bots, scanners). Read from the newest part "
        "of the log; check window_complete and data_starts_at before "
        "claiming anything about the whole window."
    ),
    args_schema=TrafficArgs,
)
