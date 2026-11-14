from app.services import net_service, sessions_service


def test_classify_bind():
    assert net_service.classify_bind("0.0.0.0") == "all_interfaces"
    assert net_service.classify_bind("::") == "all_interfaces"
    assert net_service.classify_bind("127.0.0.1") == "loopback"
    assert net_service.classify_bind("10.0.0.4") == "specific"


def test_count_remote_sessions():
    users = [
        {"user": "ubuntu", "from_host": "198.51.100.4"},
        {"user": "ubuntu", "from_host": "local"},
        {"user": "root", "from_host": "203.0.113.9"},
    ]

    assert sessions_service.count_remote_sessions(users) == 2
    assert sessions_service.count_remote_sessions([]) == 0
