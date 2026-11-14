from app.services import vps_auth_service as svc


LINES = [
    "2026-11-14T09:00:01 valtoria sshd[901]: Accepted publickey for ubuntu "
    "from 198.51.100.4 port 50122 ssh2",
    "2026-11-14T09:01:02 valtoria sshd[902]: Failed password for invalid "
    "user admin;rm from 203.0.113.9 port 4022 ssh2",
    "2026-11-14T09:01:03 valtoria sshd[903]: Failed password for root "
    "from 203.0.113.9 port 4023 ssh2",
    "2026-11-14T09:01:04 valtoria sshd[904]: Failed password for root "
    "from not-an-ip port 4024 ssh2",
    "2026-11-14T09:02:00 valtoria CRON[1]: session opened for user root",
]


def test_parse_events_and_cleaning():
    accepted, failed = svc.parse_events(LINES)

    assert accepted == [{
        "time": "2026-11-14T09:00:01",
        "method": "publickey",
        "user": "ubuntu",
        "ip": "198.51.100.4",
    }]
    assert len(failed) == 3
    assert failed[0]["user"] == "admin_rm"
    assert failed[2]["ip"] == "invalid"


def test_top_counts_orders_by_attempts():
    _, failed = svc.parse_events(LINES)
    top = svc.top_counts([event["ip"] for event in failed], "ip")

    assert top[0] == {"ip": "203.0.113.9", "attempts": 2}
