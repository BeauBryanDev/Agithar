import pytest

from app.ingestion.nginx_log_feed import NginxFeed
from app.ingestion.static_assets import is_plain_asset
from tests.conftest import FakeRegistry


HOST = "spring-bloom.tensorkingdom.com"
CLIENT = "2800:484:8b6c:8978:1fc4:94dc:aa06:3c36"


@pytest.mark.parametrize(
    "target",
    [
        "/assets/icons/send_icon.svg",
        "/favicon.svg",
        "/assets/img/Logo-Dark.SVG",
        "/css/style.css",
        "/js/app.min.js",
        "/fonts/inter-v12.woff2",
        "/assets/icons/send_icon.svg?v=3",
        "/assets/app.js?v=1.2.3&lang=en",
    ],
)
def test_plain_assets_are_skipped(target):
    assert is_plain_asset("GET", target) is True


@pytest.mark.parametrize(
    "method, target",
    [
        ("GET", "/assets/<svg onload=alert(1)>.svg"),
        ("GET", "/assets/icons/../../../etc/passwd.svg"),
        ("GET", "/x.svg/%2e%2e/%2e%2e/etc/passwd"),
        ("GET", "/assets/%2e%2e/x.svg"),
        ("GET", "/assets//x.svg"),
        ("GET", "/.git/x.svg"),
        ("GET", "/icons/x.svg?q=%3Cscript%3E"),
        ("GET", "/icons/x.svg?q=<script>"),
        ("GET", "/icons/x.svg?"),
        ("GET", "/icons/x.svg#frag"),
        ("GET", "http://evil.example/x.svg"),
        ("GET", "/icons/x.svg;jsessionid=1"),
        ("GET", "/products?category=roses"),
        ("GET", "/download.php"),
        ("GET", "/" + "a" * 400 + ".svg"),
        ("POST", "/assets/icons/send_icon.svg"),
        (None, "/assets/icons/send_icon.svg"),
        ("GET", None),
    ],
)
def test_anything_unusual_is_still_scored(method, target):
    assert is_plain_asset(method, target) is False


def nginx_line(target: str, second: int = 0) -> str:
    return (
        f'{CLIENT} "-" [2026-11-14T12:02:{second:02d}+00:00] "{HOST}" '
        f'"GET {target} HTTP/1.1" 200 512 "Mozilla/5.0"'
    )


def make_feed(registry) -> NginxFeed:
    return NginxFeed(
        registry, None, None, None,
        hosts=[HOST], ignore_ips=[], log_only=True,
    )


def test_feed_skips_assets_for_payload_but_keeps_them_for_recon():
    registry = FakeRegistry({"http_payload_sensor": 0.99, "recon_sensor": 0.1})
    feed = make_feed(registry)
    lines = [
        nginx_line("/assets/icons/send_icon.svg", 1),
        nginx_line("/assets/icons/cart.svg", 2),
        nginx_line("/search?q=%3Cscript%3E", 3),
    ]
    pending = feed.process(lines, idle=False)
    scored = [payload["url"] for _, payload in registry.calls]

    assert scored == ["/search?q=%3Cscript%3E"]
    assert feed.stats["static_assets"] == 2
    assert feed.stats["scored_requests"] == 1
    assert len(pending) == 1
    assert sum(len(w.requests) for w in feed.windows._open.values()) == 3


@pytest.mark.models
def test_incident_path_no_longer_flagged_with_real_model():
    from app.sensors.registry import load_default_registry

    registry = load_default_registry()
    feed = make_feed(registry)
    pending = feed.process(
        [
            nginx_line("/assets/icons/send_icon.svg", 1),
            nginx_line("/assets/<svg/onload=alert(1)>.svg", 2),
        ],
        idle=False,
    )
    flagged = [item.target for item in pending]

    assert registry.predict(
        "http_payload_sensor", {"url": "/assets/icons/send_icon.svg"}
    ).score > 0.9
    assert flagged == ["/assets/<svg/onload=alert(1)>.svg"]
