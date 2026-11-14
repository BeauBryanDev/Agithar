import re
from datetime import date
from typing import Any

import yaml

from app.security.sanitize import sanitize_string

MAX_TITLE_CHARS = 200
MAX_DESCRIPTION_CHARS = 600
MAX_AUTHOR_CHARS = 200
MAX_DETECTION_CHARS = 3000
MAX_FIELD_CHARS = 64
MAX_LIST_ITEMS = 5
MAX_ITEM_CHARS = 200
MAX_REFERENCE_CHARS = 300
MAX_TAGS = 40
RULE_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
TECHNIQUE_TAG = re.compile(r"^attack\.(t[0-9]{4}(?:\.[0-9]{3})?)$")
CVE_TAG = re.compile(r"^cve\.([0-9]{4})[-.]([0-9]{4,7})$")
TACTIC_TAG = re.compile(r"^attack\.([a-z]+(?:-[a-z]+){0,3})$")
REFERENCE = re.compile(r"^https://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$")
LOGSOURCE_VALUE = re.compile(r"^[a-z0-9_.-]{1,64}$")
STATUSES = ("stable", "test", "experimental")
LEVELS = ("critical", "high", "medium", "low", "informational")
COLLECTIONS = {
    "rules": "core",
    "rules-emerging-threats": "emerging-threats",
    "rules-threat-hunting": "threat-hunting",
    "rules-compliance": "compliance",
}
PLATFORMS = (
    "linux",
    "web",
    "network",
    "cloud",
    "macos",
    "windows",
    "other",
)
# Only these are indexed: the protected servers are Linux hosts behind
# a web server in a cloud account. Windows and macOS rules are left out.
INDEXED_PLATFORMS = ("linux", "web", "network", "cloud", "other")
OS_PRODUCTS = ("linux", "windows", "macos")
WEB_CATEGORIES = ("webserver", "proxy")
NETWORK_CATEGORIES = ("firewall", "dns", "network_connection")
NETWORK_PRODUCTS = ("zeek", "cisco", "juniper", "huawei", "fortios")
CLOUD_PRODUCTS = (
    "aws",
    "azure",
    "gcp",
    "m365",
    "okta",
    "github",
    "google_workspace",
    "onelogin",
    "kubernetes",
    "bitbucket",
)


def clean(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""

    return sanitize_string(value, limit).strip()


def clean_date(value: Any) -> str:
    # YAML already turns 2022-12-28 into a date object.
    if isinstance(value, date):
        return value.isoformat()

    try:
        return date.fromisoformat(str(value).strip()).isoformat()

    except ValueError:
        return ""


def logsource_value(logsource: dict, key: str) -> str:
    value = str(logsource.get(key) or "").strip().lower()

    if LOGSOURCE_VALUE.match(value):
        return value

    return ""


def classify_platform(product: str, category: str, path: str) -> str:
    if product in OS_PRODUCTS:
        return product

    if category in WEB_CATEGORIES or "/web/" in path:
        return "web"

    if product in CLOUD_PRODUCTS or "/cloud/" in path:
        return "cloud"

    if product in NETWORK_PRODUCTS or category in NETWORK_CATEGORIES:
        return "network"

    if "/network/" in path:
        return "network"

    return "other"


def split_tags(tags: Any) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {
        "techniques": [],
        "cves": [],
        "tactics": [],
    }

    if not isinstance(tags, list):
        return found

    for raw in tags[:MAX_TAGS]:
        tag = str(raw).strip().lower()
        technique = TECHNIQUE_TAG.match(tag)
        cve = CVE_TAG.match(tag)
        tactic = TACTIC_TAG.match(tag)

        if technique:
            found["techniques"].append(technique.group(1).upper())

        elif cve:
            found["cves"].append(f"CVE-{cve.group(1)}-{cve.group(2)}")

        elif tactic:
            found["tactics"].append(tactic.group(1))

    return found


def clean_list(values: Any, limit: int) -> list[str]:
    if not isinstance(values, list):
        return []

    cleaned = []

    for value in values:
        text = clean(value, limit)

        if text:
            cleaned.append(text)

        if len(cleaned) == MAX_LIST_ITEMS:
            break

    return cleaned


def clean_references(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []

    kept = []

    for value in values:
        text = str(value).strip()

        if len(text) <= MAX_REFERENCE_CHARS and REFERENCE.match(text):
            kept.append(text)

        if len(kept) == MAX_LIST_ITEMS:
            break

    return kept


def dump_detection(detection: Any) -> tuple[str, bool]:
    # The detection block is kept as YAML text: it is shown, never executed.
    if not isinstance(detection, dict):
        return "", False

    text = yaml.safe_dump(
        detection, sort_keys=False, allow_unicode=True, width=100
    )
    truncated = len(text) > MAX_DETECTION_CHARS
    cleaned = sanitize_string(text, MAX_DETECTION_CHARS, keep_newlines=True)

    return cleaned.rstrip(), truncated


def collection_of(path: str) -> str | None:
    return COLLECTIONS.get(path.split("/", 1)[0])


def rank_of(status: str, level: str) -> int:
    # Lower is better: mature and severe rules are listed first.
    status_rank = STATUSES.index(status) if status in STATUSES else 3
    level_rank = LEVELS.index(level) if level in LEVELS else 5

    return status_rank * 10 + level_rank


def parse_rule(document: Any, path: str) -> dict[str, Any] | None:
    collection = collection_of(path)

    if not isinstance(document, dict) or collection is None:
        return None

    rule_id = str(document.get("id") or "").strip().lower()
    title = clean(document.get("title"), MAX_TITLE_CHARS)
    detection, truncated = dump_detection(document.get("detection"))

    if not RULE_ID.match(rule_id) or not title or not detection:
        return None

    logsource = document.get("logsource")

    if not isinstance(logsource, dict):
        logsource = {}

    product = logsource_value(logsource, "product")
    category = logsource_value(logsource, "category")
    status = str(document.get("status") or "").strip().lower()
    level = str(document.get("level") or "").strip().lower()
    tags = split_tags(document.get("tags"))

    return {
        "rule_id": rule_id,
        "title": title,
        "description": clean(
            document.get("description"), 
            MAX_DESCRIPTION_CHARS
        ),
        "author": clean(document.get("author"), MAX_AUTHOR_CHARS),
        "status": status if status in STATUSES else "unknown",
        "level": level if level in LEVELS else "unknown",
        "rank": rank_of(status, level),
        "date": clean_date(document.get("date")),
        "modified": clean_date(document.get("modified")),
        "platform": classify_platform(product, category, f"/{path}"),
        "collection": collection,
        "product": product,
        "category": category,
        "service": logsource_value(logsource, "service"),
        "tactics": sorted(set(tags["tactics"])),
        "techniques": sorted(set(tags["techniques"])),
        "cves": sorted(set(tags["cves"])),
        "detection": detection,
        "detection_truncated": truncated,
        "falsepositives": clean_list(
            document.get("falsepositives"),
            MAX_ITEM_CHARS
        ),
        "references": clean_references(document.get("references")),
        "path": clean(path, MAX_ITEM_CHARS),
    }
