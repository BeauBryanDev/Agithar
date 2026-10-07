import threading
import time
from collections import deque
from functools import lru_cache

from fastapi import HTTPException, Request, status

from app.core.config import get_settings
from app.security.client_ip import Visitor, identify


LOGIN_WINDOW_SECONDS = 900
LOGIN_IP_MAX_FAILURES = 20
LOGIN_USER_MAX_FAILURES = 5
PASSWORD_MAX_FAILURES = 5
MAX_TRACKED_KEYS = 10000

# FailureLimiter is a thread-safe rate limiter that tracks failed attempts for different keys 
#  and enforces limits on the number of failures within a specified time window. 
# It also supports eviction of old keys when the maximum number of tracked keys is reached.

class FailureLimiter:
    def __init__(
        self, max_failures: int, 
        window_seconds: int,
        max_keys: int
    ) -> None:
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.failures: dict[str, deque[float]] = {}
        self.lock = threading.Lock()

    def prune(self, key: str, now: float) -> deque[float]:
        attempts = self.failures.get(key, deque())

        while attempts and now - attempts[0] >= self.window_seconds:
            attempts.popleft()

        if not attempts:
            self.failures.pop(key, None)

        return attempts

    def evict_if_full(self, now: float) -> None:
        if len(self.failures) < self.max_keys:
            return

        for key in list(self.failures):
            self.prune(key, now)

        while len(self.failures) >= self.max_keys:
            oldest = next(iter(self.failures))
            del self.failures[oldest]

    def retry_after(self, key: str) -> int:
        now = time.monotonic()

        with self.lock:
            attempts = self.prune(key, now)

            if len(attempts) < self.max_failures:
                return 0

            wait = self.window_seconds - (now - attempts[0])
            return max(int(wait) + 1, 1)

    def record_failure(self, key: str) -> None:
        now = time.monotonic()

        with self.lock:
            attempts = self.prune(key, now)

            if key not in self.failures:
                self.evict_if_full(now)
                self.failures[key] = attempts

            attempts.append(now)

    def reset(self, key: str) -> None:
        with self.lock:
            self.failures.pop(key, None)

    def clear(self) -> None:
        with self.lock:
            self.failures.clear()


LOGIN_IP_LIMITER = FailureLimiter(
    LOGIN_IP_MAX_FAILURES, 
    LOGIN_WINDOW_SECONDS, 
    MAX_TRACKED_KEYS
)
LOGIN_USER_LIMITER = FailureLimiter(
    LOGIN_USER_MAX_FAILURES, 
    LOGIN_WINDOW_SECONDS,
    MAX_TRACKED_KEYS
)
PASSWORD_LIMITER = FailureLimiter(
    PASSWORD_MAX_FAILURES, 
    LOGIN_WINDOW_SECONDS, 
    MAX_TRACKED_KEYS
)


class UsageLimiter:
    # At most max_events per window for each key (an LLM chat message costs
    # money, so every use counts, not only failures). Thread-safe.
    def __init__(
        self,
        max_events: int,
        window_seconds: int,
        max_keys: int = MAX_TRACKED_KEYS,
    ) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self.events: dict[str, deque[float]] = {}
        self.lock = threading.Lock()

    def hit(self, key: str, now: float | None = None) -> int:
        # 0 when allowed (and recorded), else the seconds to wait.
        moment = time.monotonic() if now is None else now

        with self.lock:
            if key not in self.events and len(self.events) >= self.max_keys:
                self.events.pop(next(iter(self.events)))

            recent = self.events.setdefault(key, deque())

            while recent and moment - recent[0] >= self.window_seconds:
                recent.popleft()

            if len(recent) >= self.max_events:
                return max(1, int(self.window_seconds - (moment - recent[0])))

            recent.append(moment)

            return 0


def remaining_events(limiter: "UsageLimiter", key: str) -> int:
    # How many more events this key may use right now (does not count one).
    now = time.monotonic()

    with limiter.lock:
        recent = limiter.events.get(key, deque())
        used = sum(1 for t in recent if now - t < limiter.window_seconds)

    return max(limiter.max_events - used, 0)


def client_ip(request: Request) -> str:
    # The key a limiter counts for this client: the real visitor address
    # (its /64 for IPv6) even behind Cloudflare and our own nginx, with the
    # same trust rule as the log parser (security/client_ip.identify). A
    # client that cannot be identified shares one bucket, never the proxy's.
    return identify(request).key


@lru_cache
def public_visitor_limiter() -> UsageLimiter:
    settings = get_settings()

    return UsageLimiter(
        settings.public_chat_ip_limit, settings.public_chat_ip_window_seconds
    )


@lru_cache
def visitor_token_limiter() -> UsageLimiter:
    # How often one visitor may ask for a guest token (it costs nothing, but
    # a script should not be able to mint them without end).
    return UsageLimiter(get_settings().public_visitor_tokens_per_hour, 3600)


def use_visitor_quota(visitor: Visitor) -> int:
    # 0 when the visitor may go on (and one use is counted), otherwise the
    # number of seconds to wait.
    return public_visitor_limiter().hit(visitor.key)


def visitor_quota_left(visitor: Visitor) -> int:
    return remaining_events(public_visitor_limiter(), visitor.key)


def too_many_requests(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many failed attempts, try again later",
        headers={"Retry-After": str(wait)},
    )


def ensure_not_limited(limiter: FailureLimiter, key: str) -> None:
    wait = limiter.retry_after(key)

    if wait > 0:
        raise too_many_requests(wait)


def too_many_messages(wait: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many chat messages, slow down",
        headers={"Retry-After": str(wait)},
    )
