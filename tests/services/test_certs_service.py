import pytest

from app.services import certs_service as svc


@pytest.mark.parametrize(
    "name, host, expected",
    [
        ("*.tensorkingdom.com", "maisonroast.tensorkingdom.com", True),
        ("*.tensorkingdom.com", "a.b.tensorkingdom.com", False),
        ("*.tensorkingdom.com", "tensorkingdom.com", False),
        ("tensorkingdom.com", "tensorkingdom.com", True),
        ("*.evil.com", "tensorkingdom.com.evil.com", False),
    ],
)
def test_name_covers(name, host, expected):
    assert svc.name_covers(name, host) is expected


def test_classify_days_thresholds():
    assert svc.classify_days(svc.CRITICAL_DAYS) == "critical"
    assert svc.classify_days(svc.WARNING_DAYS) == "warning"
    assert svc.classify_days(svc.WARNING_DAYS + 1) == "ok"
    assert svc.classify_days(-5) == "critical"


def test_shared_certificates_groups_by_fingerprint():
    rows = [
        {"site": "shop", "fingerprint": "aa"},
        {"site": "api", "fingerprint": "aa"},
        {"site": "other", "fingerprint": "bb"},
        {"site": "down"},
    ]

    assert svc.shared_certificates(rows) == [
        {"fingerprint": "aa", "sites": ["shop", "api"]}
    ]
