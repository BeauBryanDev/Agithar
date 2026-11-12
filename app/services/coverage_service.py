import re
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from app.core.logging import get_logger
from app.db.postgresql import repository
from app.db.postgresql.session import (
    DatabaseNotConfiguredError,
    get_session_factory,
)
from app.rag import mitre_attack
from app.sensors.catalog import LIVE_SENSORS, PROFILES
from app.services import sigma_service
from app.utils import coverage_build

INCIDENT_WINDOW_DAYS = 30
CACHE_SECONDS = 60.0
MAX_GAPS = 8
SENSOR_TECHNIQUE = re.compile(r"^(T[0-9]{4}(?:\.[0-9]{3})?)\b")
RULE_COLUMNS = (
    "technique",
    "rule_id",
    "title",
    "platform",
    "product",
    "category",
    "service",
)
RULES_SQL = (
    "SELECT t.tag, r.rule_id, r.title, r.platform, r.product, r.category, "
    "r.service FROM rule_tags t JOIN rules r ON r.rule_id = t.rule_id "
    "WHERE t.tag LIKE 'T%' ORDER BY r.rank, r.title"
)
COLLECTED_LOGS = ["nginx access log (webserver)", "auth.log (sshd, sudo)"]
DESCRIPTION = (
    "Detection coverage of the protected Linux servers. Level 3: watched "
    "by a live Agithar sensor. Level 2: public Sigma rules exist for a log "
    "that is collected, but they are not deployed. Level 1: rules exist "
    "but need a log that is not collected. Level 0: nothing."
)


logger = get_logger("services.coverage")


class CoverageError(Exception):
    pass


_cache: dict[str, Any] = {"at": 0.0, "value": None}
_lock = threading.Lock()


def load_rules() -> list[dict[str, str]]:
    rows = sigma_service.fetch_all(RULES_SQL)

    return [dict(zip(RULE_COLUMNS, row)) for row in rows]


def sensor_techniques() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    live: dict[str, list[str]] = {}
    offline: dict[str, list[str]] = {}

    for name, profile in PROFILES.items():
        match = SENSOR_TECHNIQUE.match(str(profile.get("mitre") or ""))

        if match is None:
            continue

        target = live if name in LIVE_SENSORS else offline
        target.setdefault(match.group(1), []).append(name)

    return live, offline


def confirmed_technique(row: Any) -> str | None:
    verdict = row.verdict if isinstance(row.verdict, dict) else {}

    if verdict.get("verdict") == "false_positive":
        return None

    technique = mitre_attack.normalize_id(verdict.get("mitre_technique"))

    return technique


def seen_techniques() -> tuple[dict[str, int], bool]:
    # A database that is down must not hide the rest of the picture.
    since = datetime.now(timezone.utc) - timedelta(days=INCIDENT_WINDOW_DAYS)

    try:
        with get_session_factory()() as session:
            rows = repository.incidents_since(session, since)

    except (SQLAlchemyError, DatabaseNotConfiguredError) as exc:
        logger.warning("coverage without incidents: %s", type(exc).__name__)

        return {}, False

    counts: Counter[str] = Counter()

    for row in rows:
        technique = confirmed_technique(row)

        if technique:
            counts[technique] += 1

    return dict(counts), True


def build_coverage() -> dict[str, Any]:
    try:
        techniques = mitre_attack.get_index()["techniques"]

    except mitre_attack.MitreError:
        raise CoverageError("the ATT&CK index is unavailable") from None

    try:
        rules = load_rules()
        sigma = sigma_service.attribution()

    except sigma_service.SigmaLookupError:
        raise CoverageError("the sigma rule index is unavailable") from None

    live, offline = sensor_techniques()
    seen, incidents_available = seen_techniques()
    rows = coverage_build.build_matrix(techniques, rules, live, offline, seen)

    return {
        "summary": coverage_build.summarize(rows),
        "collected_logs": list(COLLECTED_LOGS),
        "incident_window_days": INCIDENT_WINDOW_DAYS,
        "incidents_available": incidents_available,
        "attack_version": mitre_attack.attack_version(),
        "sigma_commit": sigma["source_commit"],
        "attribution": [mitre_attack.attribution(), sigma["source"]],
        "rows": rows,
    }


def get_coverage() -> dict[str, Any]:
    with _lock:
        now = time.monotonic()

        if _cache["value"] is None or now - _cache["at"] > CACHE_SECONDS:
            _cache["value"] = build_coverage()
            _cache["at"] = now

        return _cache["value"]


def navigator_layer() -> dict[str, Any]:
    coverage = get_coverage()

    return coverage_build.build_layer(
        coverage["rows"], coverage["attack_version"], DESCRIPTION
    )


def brief(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "technique": row["technique"],
        "name": row["name"],
        "rules": row["rules"],
        "usable_rules": row["usable_rules"],
        "missing_logs": row["missing_logs"],
        "incidents": row["incidents"],
        "threat_groups": row["threat_groups"],
    }


def overview() -> dict[str, Any]:
    # The short view for the agent: totals and the gaps worth closing first.
    coverage = get_coverage()
    rows = coverage["rows"]
    build = coverage_build
    covered = build.top_gaps(rows, build.LEVEL_COVERED, MAX_GAPS)
    ready = build.top_gaps(rows, build.LEVEL_RULE_READY, MAX_GAPS)
    log_missing = build.top_gaps(rows, build.LEVEL_LOG_MISSING, MAX_GAPS)
    blind = build.top_gaps(rows, build.LEVEL_BLIND, MAX_GAPS)

    return {
        "summary": coverage["summary"],
        "collected_logs": coverage["collected_logs"],
        "incidents_available": coverage["incidents_available"],
        "covered_by_sensors": [
            {**brief(row), "sensors": row["sensors"]} for row in covered
        ],
        "rules_ready_not_deployed": [brief(row) for row in ready],
        "rules_need_new_logs": [brief(row) for row in log_missing],
        "blind": [brief(row) for row in blind],
        "note": (
            "Gap lists hold the top entries only, ranked by our own "
            "incidents and then by how many threat groups use the "
            "technique. Sigma rules are not deployed on this server."
        ),
    }


def technique_coverage(technique_id: str) -> dict[str, Any]:
    clean_id = mitre_attack.normalize_id(technique_id)

    if clean_id is None:
        raise CoverageError("invalid technique id")

    for row in get_coverage()["rows"]:
        if row["technique"] == clean_id:
            return {"in_scope": True, "coverage": row}

    return {
        "in_scope": False,
        "technique": mitre_attack.check_technique(clean_id),
        "note": "Not a Linux technique and nothing here relates to it.",
    }
