import re
from datetime import datetime, timezone
from typing import Any

from app.schemas.vulnerabilities import (
    MAX_CWES,
    MAX_REFERENCES,
    MAX_URL_CHARS,
    CVSSScore,
    VulnerabilityRead,
)

METRIC_KEYS = (
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
)
VERSIONS = frozenset({"4.0", "3.1", "3.0", "2.0"})
SEVERITIES = frozenset({"none", "low", "medium", "high", "critical"})
CWE_VALUE = re.compile(r"^CWE-[0-9]{1,5}$")
VECTOR_VALUE = re.compile(r"^[A-Za-z0-9:/._-]{1,128}$")


def severity_from_score(score: float) -> str:
    if score == 0.0:
        return "none"

    if score < 4.0:
        return "low"

    if score < 7.0:
        return "medium"

    return "high" if score < 9.0 else "critical"


def build_cvss(entry: dict[str, Any]) -> CVSSScore | None:
    data = entry.get("cvssData")

    if not isinstance(data, dict):
        return None

    version = str(data.get("version", ""))
    score = data.get("baseScore")

    if version not in VERSIONS or isinstance(score, bool):
        return None

    if not isinstance(score, (int, float)) or not 0.0 <= score <= 10.0:
        return None

    severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "")
    vector = data.get("vectorString")

    return CVSSScore(
        version=version,
        base_score=float(score),
        severity=(
            severity.lower()
            if severity.lower() in SEVERITIES
            else severity_from_score(float(score))
        ),
        vector=vector if isinstance(vector, str) and VECTOR_VALUE.match(vector)
        else None,
    )


def pick_cvss(metrics: Any) -> CVSSScore | None:
    if not isinstance(metrics, dict):
        return None

    for key in METRIC_KEYS:
        entries = metrics.get(key)

        if not isinstance(entries, list) or not entries:
            continue

        primary = [e for e in entries if isinstance(e, dict)
                   and e.get("type") == "Primary"]
        candidate = (primary or entries)[0]
        cvss = build_cvss(candidate) if isinstance(candidate, dict) else None

        if cvss is not None:
            return cvss

    return None


def parse_time(value: Any) -> datetime | None:
    # NVD times carry no zone; they are UTC.
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None

    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def english_description(descriptions: Any) -> str:
    if not isinstance(descriptions, list):
        return ""

    for item in descriptions:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value", ""))

    return ""


def pick_cwes(weaknesses: Any) -> list[str]:
    found: list[str] = []

    for weakness in weaknesses if isinstance(weaknesses, list) else []:
        for item in weakness.get("description", []) if isinstance(
            weakness, dict
        ) else []:
            value = item.get("value") if isinstance(item, dict) else None

            if isinstance(value, str) and CWE_VALUE.match(value):
                if value not in found:
                    found.append(value)

    return found[:MAX_CWES]


def pick_references(references: Any) -> list[str]:
    links: list[str] = []

    for item in references if isinstance(references, list) else []:
        url = item.get("url") if isinstance(item, dict) else None

        if isinstance(url, str) and url.startswith("https://"):
            if len(url) <= MAX_URL_CHARS and url not in links:
                links.append(url)

    return links[:MAX_REFERENCES]


def parse_nvd(body: Any, cve_id: str) -> VulnerabilityRead | None:
    if not isinstance(body, dict):
        return None

    items = body.get("vulnerabilities")

    if not isinstance(items, list) or not items:
        return None

    cve = items[0].get("cve") if isinstance(items[0], dict) else None

    if not isinstance(cve, dict) or cve.get("id") != cve_id:
        return None

    return VulnerabilityRead(
        cve_id=cve_id,
        summary=english_description(cve.get("descriptions")),
        cvss=pick_cvss(cve.get("metrics")),
        cwes=pick_cwes(cve.get("weaknesses")),
        published=parse_time(cve.get("published")),
        modified=parse_time(cve.get("lastModified")),
        references=pick_references(cve.get("references")),
    )
