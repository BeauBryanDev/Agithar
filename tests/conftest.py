import sys
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import app.db.postgresql.incidents  # noqa: F401  registers the tables
from app.core import auth
from app.core.config import get_settings
from app.db.postgresql.users import Base
from app.schemas.analysis import AgentVerdict


FAKE_SECRETS = {
    "abuseipdb_api_key": SecretStr("abuse-test-key-0000"),
    "shodan_api_key": SecretStr("shodan-test-key-0000"),
    "virustotal_api_key": SecretStr("vt-test-key-0000"),
    "telegram_bot_token": SecretStr(
        "123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ),
    "telegram_chat_id": "424242",
    "nvd_api_key": None,
    "database_url": None,
}

HTTP_HANDLER: list[Callable[[httpx.Request], httpx.Response]] = []
REAL_ASYNC_CLIENT = httpx.AsyncClient


def refuse_network(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unmocked HTTP request to {request.url.host}")


def dispatch(request: httpx.Request) -> httpx.Response:
    handler = HTTP_HANDLER[-1] if HTTP_HANDLER else refuse_network
    return handler(request)


class GuardedAsyncClient(REAL_ASYNC_CLIENT):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs["transport"] = httpx.MockTransport(dispatch)
        super().__init__(*args, **kwargs)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(httpx, "AsyncClient", GuardedAsyncClient)
    HTTP_HANDLER.clear()
    yield
    HTTP_HANDLER.clear()


@pytest.fixture
def mock_http() -> Callable[[Callable], list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def install(handler: Callable) -> list[httpx.Request]:
        def record(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return handler(request)

        HTTP_HANDLER.append(record)
        return seen

    return install


@pytest.fixture(autouse=True)
def settings(monkeypatch: pytest.MonkeyPatch, tmp_path) -> Any:
    fake = get_settings().model_copy(update=dict(FAKE_SECRETS))

    def fake_settings() -> Any:
        return fake

    for name, module in list(sys.modules.items()):
        if name.startswith("app.") and hasattr(module, "get_settings"):
            monkeypatch.setattr(module, "get_settings", fake_settings)

    return fake


@pytest.fixture(autouse=True)
def fast_bcrypt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "BCRYPT_ROUNDS", 4)


@pytest.fixture
def db_session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def make_case(**overrides: Any) -> dict[str, Any]:
    case = {
        "case_id": "198.51.100.7:29000000",
        "ip": "198.51.100.7",
        "window_bucket": 29000000,
        "window_seconds": 60,
        "severity": "high",
        "composite_score": 0.93,
        "num_sensors": 2,
        "num_strong_sensors": 2,
        "contributing_sensors": ["http_payload_sensor", "recon_sensor"],
        "sensor_scores": {"http_payload_sensor": 0.98, "recon_sensor": 0.88},
        "event_counts": {"http_payload_sensor": 3, "recon_sensor": 1},
        "evidence": [],
    }
    case.update(overrides)

    return case


def make_verdict(**overrides: Any) -> AgentVerdict:
    values = {
        "verdict": "confirmed",
        "needs_human": False,
        "confidence": 0.9,
        "mitre_technique": "T1190",
        "owasp_category": "A05:2025",
        "summary": "SQL injection attempts against the shop search.",
    }
    values.update(overrides)

    return AgentVerdict(**values)


class FakeRegistry:
    def __init__(self, scores: dict[str, float] | None = None) -> None:
        self.scores = scores or {"http_payload_sensor": 0.99}
        self.sensors = {name: object() for name in self.scores}
        self.failures: dict[str, str] = {}
        self.calls: list[tuple[str, dict]] = []

    @property
    def is_complete(self) -> bool:
        return not self.failures

    def predict(self, name: str, payload: dict) -> Any:
        from app.sensors.base import SensorResult

        self.calls.append((name, payload))
        score = self.scores[name]

        return SensorResult(
            sensor=name, score=score, is_anomalous=score >= 0.5,
            threshold=0.5,
        )


@pytest.fixture
def fake_registry() -> FakeRegistry:
    return FakeRegistry()
