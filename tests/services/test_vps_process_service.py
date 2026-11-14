from app.services import vps_process_service as svc


def test_redact_args_hides_secrets():
    args = [
        "gunicorn", "--password=hunter2", "--db-pass", "s3cret",
        "--api-key", "abc123", "DB_TOKEN=xyz",
        "postgresql://user:dbpass@localhost/db", "--workers", "3",
    ]
    text = " ".join(svc.redact_args(args))

    for secret in ("hunter2", "s3cret", "abc123", "xyz", "dbpass"):
        assert secret not in text

    assert "--workers 3" in text
    assert svc.clean_command(["sh", "-c", "echo \x1b[31m"], "sh").isprintable()


def test_find_suspicious_shell_under_web_server():
    rows = [
        {"pid": 10, "ppid": 1, "name": "nginx"},
        {"pid": 11, "ppid": 10, "name": "bash"},
        {"pid": 12, "ppid": 1, "name": "bash"},
        {"pid": 13, "ppid": 10, "name": "nginx"},
    ]
    found = svc.find_suspicious(rows)

    assert [row["pid"] for row in found] == [11]
    assert found[0]["parent"] == "nginx"
