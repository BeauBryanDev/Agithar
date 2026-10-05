import json
import re
from datetime import datetime
from typing import Any

from app.security.sanitize import sanitize_string

DATE_FORMAT = "%B %d, %Y at %H:%M UTC"
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_DESCRIPTION_CHARS = 2000
MAX_PRODUCTS_CHARS = 800
MAX_FIELD_CHARS = 120
MAX_REFERENCES = 20
MAX_REFERENCE_CHARS = 512
MAX_CWES = 10
MAX_PARSE_CHARS = 200_000
CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
LAST_UPDATED = re.compile(r"^- \*\*Last Updated\*\*: (.+)$", re.MULTILINE)
CVSS_SCORE = re.compile(
    r"^- \*\*CVSS Base Score\*\*: ([0-9]{1,2}(?:\.[0-9])?)/10", re.MULTILINE
)
CVSS_SEVERITY = re.compile(r"^- \*\*Severity\*\*: ([A-Za-z]+)", re.MULTILINE)
CVSS_VECTOR = re.compile(
    r"^- \*\*CVSS Vector\*\*: `([^`]{1,128})`", re.MULTILINE
)
CWE_LINE = re.compile(r"^- (CWE-[0-9]{1,5})\b", re.MULTILINE)
REFERENCE_LINE = re.compile(
    r"^[0-9]+\. \[[^\]]*\]\((https://[^)\s]+)\)", re.MULTILINE
)
HEADING = re.compile(r"^### (.+)$", re.MULTILINE)
SEVERITIES = frozenset({"none", "low", "medium", "high", "critical"})
VECTOR_VERSIONS = {
    "CVSS:3.1/": "3.1",
    "CVSS:3.0/": "3.0",
    "CVSS:4.0/": "4.0",
    "AV:": "2.0",
}


def parse_date(text: str | None) -> str:
    try:
        return datetime.strptime((text or "").strip(), 
                                 DATE_FORMAT).strftime(
            ISO_FORMAT
        )
    except ValueError:
        return ""


def section(full_record: str, heading: str) -> str:
    # Text between a "### heading" line and the next "### " line.
    matches = list(HEADING.finditer(full_record))

    for index, match in enumerate(matches):
        if match.group(1).startswith(heading):
            end = (
                matches[index + 1].start()
                if index + 1 < len(matches)
                else len(full_record)
            )

            return full_record[match.end():end]

    return ""


def parse_cvss(full_record: str) -> dict[str, Any] | None:
    block = section(full_record, "CVSS Metrics")
    score = CVSS_SCORE.search(block)
    vector = CVSS_VECTOR.search(block)

    if not score or not vector:
        return None

    version = None

    for prefix, found in VECTOR_VERSIONS.items():
        if vector.group(1).startswith(prefix):
            version = found
            break

    value = float(score.group(1))

    if version is None or not 0.0 <= value <= 10.0:
        return None

    severity_match = CVSS_SEVERITY.search(block)
    severity = severity_match.group(1).lower() if severity_match else ""

    return {
        "version": version,
        "score": value,
        "severity": severity if severity in SEVERITIES else None,
        "vector": vector.group(1),
    }


def parse_cwes(full_record: str) -> list[str]:
    block = section(full_record, "Weakness Classification")
    found = list(dict.fromkeys(CWE_LINE.findall(block)))

    return found[:MAX_CWES]


def parse_references(full_record: str) -> list[str]:
    block = section(full_record, "References")
    links = []

    for url in REFERENCE_LINE.findall(block):
        if len(url) <= MAX_REFERENCE_CHARS and url not in links:
            links.append(url)

    return links[:MAX_REFERENCES]


def clean_description(document: str, cve_id: str) -> str:
    prefix = f"{cve_id}: "

    if document.startswith(prefix):
        document = document[len(prefix):]

    return sanitize_string(document, MAX_DESCRIPTION_CHARS)


def build_row(fields: dict[str, str]) -> tuple | None:
    cve_id = fields["cve_id"].strip().upper()

    if not CVE_ID.match(cve_id):
        return None

    full_record = fields["full_record"][:MAX_PARSE_CHARS]
    modified = LAST_UPDATED.search(full_record)
    cvss = parse_cvss(full_record) or {}

    return (
        cve_id,
        parse_date(fields["published"]),
        parse_date(modified.group(1) if modified else None),
        sanitize_string(fields["vendor"], MAX_FIELD_CHARS),
        sanitize_string(fields["vuln_type"], MAX_FIELD_CHARS),
        clean_description(fields["chroma:document"], cve_id),
        cvss.get("version"),
        cvss.get("score"),
        cvss.get("severity"),
        cvss.get("vector"),
        json.dumps(parse_cwes(full_record)),
        sanitize_string(fields["products"], MAX_PRODUCTS_CHARS),
        json.dumps(parse_references(full_record)),
    )
