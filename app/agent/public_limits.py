import asyncio
import threading
from datetime import datetime, timezone
from functools import lru_cache

from app.core.config import get_settings
from app.schemas.analysis import AnalyzeRequest, AnalyzeResponse
from app.security.rate_limit import UsageLimiter
from app.sensors.registry import SensorRegistry
from app.services.analysis_service import analyze

# Budgets for the PUBLIC demo. They are global (all visitors together): they
# protect the free API keys and the CPU of the shared server no matter how
# many visitors or IPs there are. The per-visitor limit lives on the router.
PUBLIC_INPUT_MAX_CHARS = 2000
ANALYSIS_TIMEOUT_SECONDS = 10.0
SLOT_WAIT_SECONDS = 1.0
GLOBAL_KEY = "public"
NVD_WINDOW_SECONDS = 3600
ANALYSIS_WINDOW_SECONDS = 60

# Book excerpts: enough to answer, too little to copy a book page by page.
EXCERPT_CHARS = 800
OFFENSIVE_EXCERPT_CHARS = 500
EXCERPT_PASSAGES = 2
OFFENSIVE_PASSAGES = 1


class PublicBusyError(Exception):
    # An app error on purpose: its fixed text is shown to the model.
    pass


@lru_cache
def nvd_budget() -> UsageLimiter:
    return UsageLimiter(
        max(get_settings().public_nvd_per_hour, 1), 
        NVD_WINDOW_SECONDS
    )


@lru_cache
def analysis_budget() -> UsageLimiter:
    return UsageLimiter(
        get_settings().public_analyses_per_minute, 
        ANALYSIS_WINDOW_SECONDS
    )


_slots: asyncio.Semaphore | None = None


def analysis_slots() -> asyncio.Semaphore:
    global _slots

    if _slots is None:
        _slots = asyncio.Semaphore(get_settings().public_analysis_concurrency)

    return _slots


def live_nvd_allowed() -> bool:
    # True while the hour's budget lasts. Each public CVE lookup uses one
    # unit, whether or not it ends up calling NVD: that keeps it simple and
    # errs on the side of protecting the key. 0 means local data only.
    if get_settings().public_nvd_per_hour == 0:
        return False

    return nvd_budget().hit(GLOBAL_KEY) == 0


async def public_analyze(
    registry: SensorRegistry, text: str
) -> AnalyzeResponse:
    # The sensors are CPU work on a shared server: a small input, a global
    # rate, a few at a time, and a time limit.
    if analysis_budget().hit(GLOBAL_KEY) > 0:
        raise PublicBusyError(
            "The demo is busy analysing other visitors' text. "
            "Try again in a minute."
        )

    slots = analysis_slots()

    try:
        await asyncio.wait_for(slots.acquire(), 
                               timeout=SLOT_WAIT_SECONDS)

    except asyncio.TimeoutError:
        raise PublicBusyError(
            "The demo is busy analysing other visitors' text. "
            "Try again in a moment."
        ) from None

    try:
        request = AnalyzeRequest(input=text[:PUBLIC_INPUT_MAX_CHARS])

        return await asyncio.wait_for(
            asyncio.to_thread(analyze, registry, request),
            timeout=ANALYSIS_TIMEOUT_SECONDS,
        )

    except asyncio.TimeoutError:
        raise PublicBusyError("The analysis took too long.") from None

    finally:
        slots.release()


# the public chat as a whole 

CHAT_SLOT_WAIT_SECONDS = 2.0


class DailyCounter:
    # Messages of ALL visitors together, per UTC day. 0 closes the chat.
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.day = ""
        self.count = 0

    def take(self) -> bool:
        cap = get_settings().public_chat_daily_messages
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        with self.lock:
            if today != self.day:
                self.day, self.count = today, 0

            if self.count >= cap:
                return False

            self.count += 1

            return True


@lru_cache
def daily_counter() -> DailyCounter:
    return DailyCounter()


_chat_slots: asyncio.Semaphore | None = None


def chat_slots() -> asyncio.Semaphore:
    global _chat_slots

    if _chat_slots is None:
        _chat_slots = asyncio.Semaphore(get_settings().public_chat_concurrency)

    return _chat_slots
