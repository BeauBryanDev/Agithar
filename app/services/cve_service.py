import asyncio
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.core.config import get_settings
from app.core.logging import get_logger
from app.rag.owasp_top10_2025 import search_by_cwe
from app.schemas.vulnerabilities import (
    MAX_CWES,
    CVELookupRequest,
    CVELookupResult,
    CVSSScore,
    ExploitReference,
    VulnerabilityRead,
)
from app.utils import nvd_client
from app.services.exploit_db_service import ExploitDbLookupError, search_by_cve
from app.utils.nvd_parse import severity_from_score

LIVE_MODES = ("auto", "never", "always")
SQLITE_CACHE_KIB = 8192
COLUMNS = (
    "cve_id, published, modified, vendor, vuln_type, description, "
    "cvss_version, cvss_score, cvss_severity, cvss_vector, cwes, "
    "products, refs"
)
LIVE_REASONS = {
    nvd_client.STATUS_NOT_FOUND: "NVD has no record for this id",
    nvd_client.STATUS_RATE_LIMITED: "the live NVD lookup was rate limited",
    nvd_client.STATUS_UNAVAILABLE: "the live NVD lookup was unavailable",
}


logger = get_logger("services.cve")


class CveLookupError(Exception):
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
    path = get_settings().cve_db_path

    try:
        mtime = path.stat().st_mtime
        
    except OSError:
        raise CveLookupError("local cve database is missing") from None

    # A rebuilt database is picked up without restarting the server.
    if _db["connection"] is None or _db["mtime"] != mtime:
        if _db["connection"] is not None:
            _db["connection"].close()

        try:
            _db["connection"] = open_database(path)
            
        except sqlite3.Error:
            raise CveLookupError("local cve database is unreadable") from None

        _db["mtime"] = mtime

    return _db["connection"]


def query_one(sql: str, params: tuple = ()) -> tuple | None:
    with _db_lock:
        try:
            return get_connection().execute(sql, params).fetchone()
        
        except sqlite3.Error:
            raise CveLookupError("local cve database query failed") from None


def dataset_info() -> dict[str, str]:
    with _db_lock:
        try:
            rows = get_connection().execute("SELECT key, value FROM meta")
            return dict(rows.fetchall())
        
        except sqlite3.Error:
            raise CveLookupError("local cve database query failed") from None


def newest_date() -> str:
    try:
        return dataset_info().get("newest_published", "")[:10] or "unknown"
    
    except CveLookupError:
        return "unknown"


def parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    
    except ValueError:
        return None


def load_list(text: str) -> list[str]:
    try:
        value = json.loads(text)
        
    except ValueError:
        return []

    return [item for item in value if isinstance(item, str)]


def cvss_from_row(row: tuple) -> CVSSScore | None:
    version, score, severity, vector = row[6], row[7], row[8], row[9]

    if version is None or score is None:
        return None

    return CVSSScore(
        version=version,
        base_score=score,
        severity=severity or severity_from_score(score),
        vector=vector,
    )


def from_row(row: tuple) -> VulnerabilityRead:
    return VulnerabilityRead(
        cve_id=row[0],
        summary=row[5],
        cvss=cvss_from_row(row),
        cwes=load_list(row[10])[:MAX_CWES],
        published=parse_iso(row[1]),
        modified=parse_iso(row[2]),
        references=load_list(row[12]),
        vendor=row[3] or None,
        vuln_type=row[4] or None,
        affected=row[11] or None,
    )


def find_local(cve_id: str) -> VulnerabilityRead | None:
    row = query_one(f"SELECT {COLUMNS} FROM cves WHERE cve_id = ?", (cve_id,))

    return from_row(row) if row else None


def owasp_for(cwes: list[str]) -> list[str]:
    found: list[str] = []

    for cwe in cwes:
        for category in search_by_cwe(cwe):
            if category not in found:
                found.append(category)

    return found[:MAX_CWES]


async def exploits_for(cve_id: str) -> list[ExploitReference]:
    try:
        entries = await search_by_cve(cve_id)
        
    except ExploitDbLookupError:
        logger.warning("exploit-db index unavailable for a cve lookup")

        return []

    try:
        return [ExploitReference(**entry) for entry in entries]
    
    except ValidationError:
        return []


async def enrich(vulnerability: VulnerabilityRead) -> VulnerabilityRead:
    return vulnerability.model_copy(
        update={
            "owasp_categories": owasp_for(vulnerability.cwes),
            "exploits": await exploits_for(vulnerability.cve_id),
        }
    )


def merge_local_fields(
    live: VulnerabilityRead, 
    local: VulnerabilityRead | None
) -> VulnerabilityRead:
    # NVD has no vendor or product text, so those come from the dataset.
    if local is None:
        return live

    return live.model_copy(
        update={
            "vendor": local.vendor,
            "vuln_type": local.vuln_type,
            "affected": local.affected,
        }
    )


def normalize_id(cve_id: Any) -> str:
    try:
        return CVELookupRequest(cve_id=cve_id).cve_id
    
    except (ValidationError, TypeError, AttributeError):
        raise CveLookupError("invalid cve id") from None


def not_found_note(live_status: str | None) -> str:
    base = f"Not in the local dataset (CVEs published up to {newest_date()})"

    if live_status is None:
        return f"{base}; the live lookup was disabled."

    reason = LIVE_REASONS.get(live_status, "live lookup failed")

    return f"{base}, and {reason}."


async def lookup_cve(cve_id: str, live: str = "auto") -> CVELookupResult:
    clean_id = normalize_id(cve_id)

    if live not in LIVE_MODES:
        raise CveLookupError("invalid live mode")

    try:
        local = await asyncio.to_thread(find_local, clean_id)
        
    except CveLookupError:
        logger.error("local cve database unavailable")
        local = None

    lacks_cvss = local is None or local.cvss is None
    use_live = live == "always" or (live == "auto" and lacks_cvss)
    result = await nvd_client.fetch_live(clean_id) if use_live else None

    if result is not None and result.vulnerability is not None:
        
        source = "cache" if result.from_cache else "nvd"
        found = merge_local_fields(result.vulnerability, local)

        return CVELookupResult(
            found=True, 
            source=source,
            vulnerability=await enrich(found)
        )

    live_status = result.status if result is not None else None

    if local is None:
        return CVELookupResult(
            found=False, 
            source="local",
            note=not_found_note(live_status)
        )

    note = None

    if result is not None and local.cvss is None:
        
        reason = LIVE_REASONS.get(result.status, "live lookup failed")
        note = f"Local dataset record without CVSS; {reason}."

    return CVELookupResult(
        found=True,
        source="local",
        vulnerability=await enrich(local),
        note=note,
    )
