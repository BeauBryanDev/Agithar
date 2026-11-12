import json
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import escape_json, sanitize_string
from app.utils.sigma_build import INDEXED_PLATFORMS, RULE_ID

ANY_PLATFORM = "any"
MAX_RESULTS = 8
MAX_QUERY_CHARS = 120
MAX_KEYWORDS = 6
MAX_SUMMARY_CHARS = 240
MAX_SHOWN_DETECTION_CHARS = 1800
MAX_ESCAPED_DETECTION_CHARS = 4000
SQLITE_CACHE_KIB = 2048
TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,7}$")
KEYWORD = re.compile(r"[a-z0-9_]{2,40}")
LIST_COLUMNS = (
    "r.rule_id, r.title, r.description, r.author, r.status, r.level, "
    "r.platform, r.collection, r.product, r.category, r.service, "
    "r.techniques"
)
DETAIL_COLUMNS = (
    "rule_id, title, description, author, status, level, platform, "
    "collection, product, category, service, techniques, date, modified, "
    "tactics, cves, detection, detection_truncated, falsepositives, refs"
)
NOTE = (
    "Sigma rules are generic detection logic from the community. They are "
    "reference material: none of them is deployed on this server. Windows "
    "and macOS rules are not in this index."
)


logger = get_logger("services.sigma")


class SigmaLookupError(Exception):
    pass


_db: dict[str, Any] = {"connection": None, "mtime": None}
_db_lock = threading.Lock()


def open_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        f"file:{path}?mode=ro", uri=True, check_same_thread=False
    )
    connection.execute("PRAGMA query_only = ON")
    connection.execute(f"PRAGMA cache_size = -{SQLITE_CACHE_KIB}")

    return connection


def get_connection() -> sqlite3.Connection:
    path = get_settings().sigma_db_path

    try:
        mtime = path.stat().st_mtime

    except OSError:
        raise SigmaLookupError("sigma rule index is missing") from None

    # A rebuilt index is picked up without restarting the server.
    if _db["connection"] is None or _db["mtime"] != mtime:
        if _db["connection"] is not None:
            _db["connection"].close()

        try:
            _db["connection"] = open_database(path)

        except sqlite3.Error:
            raise SigmaLookupError("sigma rule index is unreadable") from None

        _db["mtime"] = mtime

    return _db["connection"]


def fetch_all(sql: str, params: tuple = ()) -> list[tuple]:
    with _db_lock:
        try:
            return get_connection().execute(sql, params).fetchall()

        except sqlite3.Error:
            logger.warning("sigma rule index query failed")
            raise SigmaLookupError("sigma rule index query failed") from None


def load_list(text: str) -> list[str]:
    try:
        values = json.loads(text)

    except ValueError:
        return []

    return [str(value) for value in values] if isinstance(values, list) else []


def summary_row(row: tuple) -> dict[str, Any]:
    return {
        "rule_id": row[0],
        "title": row[1],
        "description": sanitize_string(row[2], MAX_SUMMARY_CHARS),
        "author": row[3],
        "status": row[4],
        "level": row[5],
        "platform": row[6],
        "collection": row[7],
        "logsource": {
            "product": row[8] or None,
            "category": row[9] or None,
            "service": row[10] or None,
        },
        "techniques": load_list(row[11]),
    }


def fit_detection(text: str) -> str:
    # Escaping can multiply the size, so the escaped length is what counts.
    shown = text[:MAX_SHOWN_DETECTION_CHARS]

    while len(escape_json(shown)) > MAX_ESCAPED_DETECTION_CHARS:
        shown = shown[: len(shown) * 3 // 4]

    return shown


def detail_row(row: tuple) -> dict[str, Any]:
    rule = summary_row(row[:12])
    rule["description"] = row[2]
    rule["date"] = row[12] or None
    rule["modified"] = row[13] or None
    rule["tactics"] = load_list(row[14])
    rule["cves"] = load_list(row[15])
    rule["detection"] = fit_detection(row[16])
    rule["detection_truncated"] = bool(row[17]) or len(row[16]) > len(
        rule["detection"]
    )
    rule["falsepositives"] = load_list(row[18])
    rule["references"] = load_list(row[19])

    return rule


def attribution() -> dict[str, str]:
    rows = fetch_all("SELECT key, value FROM meta")
    meta = dict(rows)

    return {
        "source": meta.get("source", "SigmaHQ/sigma"),
        "license": meta.get("license", "Detection Rule License 1.1"),
        "source_commit": meta.get("source_commit", "unknown"),
        "note": NOTE,
    }


def tag_filter(tag: str) -> tuple[str, tuple]:
    # A parent technique also matches the rules of its sub-techniques.
    if TECHNIQUE_ID.match(tag) and "." not in tag:
        return "(t.tag = ? OR t.tag LIKE ?)", (tag, f"{tag}.%")

    return "t.tag = ?", (tag,)


def fts_expression(text: str, joiner: str) -> str | None:
    words = KEYWORD.findall(text.lower())[:MAX_KEYWORDS]

    if not words:
        return None

    # Every word is quoted, so it can never act as an FTS operator.
    return joiner.join(f'"{word}"' for word in words)


def run_search(source: str, where: str, params: tuple, order: str,
               platform: str) -> dict[str, Any]:
    counts = fetch_all(
        f"SELECT r.platform, COUNT(DISTINCT r.rule_id) FROM {source} "
        f"WHERE {where} GROUP BY r.platform",
        params,
    )
    by_platform = dict(counts)
    clause = ""
    extra: tuple = ()

    if platform != ANY_PLATFORM:
        clause = " AND r.platform = ?"
        extra = (platform,)

    rows = fetch_all(
        f"SELECT DISTINCT {LIST_COLUMNS} FROM {source} "
        f"WHERE {where}{clause} ORDER BY {order} LIMIT ?",
        (*params, *extra, MAX_RESULTS),
    )
    total = sum(by_platform.values())

    if platform != ANY_PLATFORM:
        total = by_platform.get(platform, 0)

    return {
        "platform": platform,
        "total": total,
        "rules_by_platform": by_platform,
        "rules": [summary_row(row) for row in rows],
    }


def search_by_tag(tag: str, platform: str) -> dict[str, Any]:
    where, params = tag_filter(tag)
    source = "rule_tags t JOIN rules r ON r.rule_id = t.rule_id"

    return run_search(source, where, params, "r.rank, r.title", platform)


def search_by_keywords(text: str, platform: str) -> dict[str, Any]:
    source = "rules_fts JOIN rules r ON r.rule_id = rules_fts.rule_id"
    order = "bm25(rules_fts, 0.0, 8.0, 3.0, 1.0), r.rank"
    result: dict[str, Any] = {
        "platform": platform,
        "total": 0,
        "rules_by_platform": {},
        "rules": [],
    }

    # All words first; any word only when that finds nothing.
    for joiner in (" AND ", " OR "):
        expression = fts_expression(text, joiner)

        if expression is None:
            raise SigmaLookupError("no searchable words in the query")

        result = run_search(
            source, "rules_fts MATCH ?", (expression,), order, platform
        )

        if result["rules_by_platform"]:
            break

    return result


def get_rule(rule_id: str) -> dict[str, Any]:
    rows = fetch_all(
        f"SELECT {DETAIL_COLUMNS} FROM rules WHERE rule_id = ?", (rule_id,)
    )

    if not rows:
        return {"found": False}

    return {"found": True, "rule": detail_row(rows[0])}


def find_rules(query: str, platform: str = "linux") -> dict[str, Any]:
    if platform != ANY_PLATFORM and platform not in INDEXED_PLATFORMS:
        raise SigmaLookupError("unknown platform")

    if not isinstance(query, str):
        raise SigmaLookupError("invalid query")

    text = sanitize_string(query, MAX_QUERY_CHARS).strip()

    if not text:
        raise SigmaLookupError("empty query")

    if RULE_ID.match(text.lower()):
        result = get_rule(text.lower())
        result["query_type"] = "rule_id"

    elif TECHNIQUE_ID.match(text.upper()):
        result = search_by_tag(text.upper(), platform)
        result["query_type"] = "technique"

    elif CVE_ID.match(text.upper()):
        result = search_by_tag(text.upper(), ANY_PLATFORM)
        result["query_type"] = "cve"

    else:
        result = search_by_keywords(text, platform)
        result["query_type"] = "keywords"

    result["attribution"] = attribution()

    return result
