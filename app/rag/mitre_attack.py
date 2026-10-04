
import copy
import json
import re
import threading
from pathlib import Path
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string

MAX_INDEX_BYTES = 20 * 1024 * 1024
MAX_QUERY_CHARS = 100
DEFAULT_LIMIT = 10
MAX_LIMIT = 50
TECHNIQUE_ID = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
REQUIRED_KEYS = ("meta", "tactics", "techniques", "revoked")
BUILD_HINT = "run scripts/build_attack_index.py"


logger = get_logger("rag.mitre_attack")


class MitreError(Exception):
    pass


_state: dict[str, Any] = {"index": None, "mtime": None}
_lock = threading.Lock()


def read_index(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_INDEX_BYTES:
            raise MitreError("attack index is too large")

        index = json.loads(path.read_text(encoding="utf-8"))
        
    except OSError:
        raise MitreError(f"attack index not found, {BUILD_HINT}") from None
    
    except ValueError:
        raise MitreError(f"attack index is invalid, {BUILD_HINT}") from None

    if not isinstance(index, dict):
        raise MitreError(f"attack index is invalid, {BUILD_HINT}")

    if any(key not in index for key in REQUIRED_KEYS):
        raise MitreError(f"attack index has the wrong shape, {BUILD_HINT}")

    return index


def get_index() -> dict[str, Any]:
    
    path = get_settings().mitre_index_path

    with _lock:
        try:
            mtime = path.stat().st_mtime
            
        except OSError:
            raise MitreError(f"attack index not found, {BUILD_HINT}") from None

        # A rebuilt index is picked up without restarting the server.
        if _state["index"] is None or _state["mtime"] != mtime:
            
            _state["index"] = read_index(path)
            _state["mtime"] = mtime
            logger.info(
                "attack index loaded",
                extra={"techniques": len(_state["index"]["techniques"])},
            )

        return _state["index"]


def normalize_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    candidate = value.strip().upper()

    return candidate if TECHNIQUE_ID.match(candidate) else None


def clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIMIT))


def summarize(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry["id"],
        "name": entry["name"],
        "tactics": list(entry["tactics"]),
        "is_subtechnique": entry["is_subtechnique"],
        "parent": entry["parent"],
    }


def attack_version() -> str:
    return str(get_index()["meta"]["attack_version"])


def attribution() -> str:
    meta = get_index()["meta"]

    return (
        f"MITRE ATT&CK Enterprise v{meta['attack_version']}. "
        f"{meta['copyright']}"
    )


def lookup(technique_id: str) -> dict[str, Any] | None:
    clean_id = normalize_id(technique_id)

    if clean_id is None:
        return None

    entry = get_index()["techniques"].get(clean_id)

    return copy.deepcopy(entry) if entry else None


def check_technique(technique_id: str) -> dict[str, Any]:
    clean_id = normalize_id(technique_id)

    if clean_id is None:
        return {"status": "invalid_format"}

    index = get_index()
    entry = index["techniques"].get(clean_id)

    if entry:
        return {
            "status": "active",
            "id": clean_id,
            "name": entry["name"],
            "tactics": list(entry["tactics"]),
        }

    old = index["revoked"].get(clean_id)

    if old:
        new_entry = index["techniques"].get(old["replaced_by"], {})

        return {
            "status": "revoked",
            "id": clean_id,
            "name": old["name"],
            "replacement": old["replaced_by"],
            "replacement_name": new_entry.get("name", ""),
        }

    return {"status": "unknown", "id": clean_id}


def list_tactics() -> list[dict[str, str]]:
    tactics = get_index()["tactics"]
    rows = []

    for shortname, tactic in tactics.items():
        rows.append(
            {
                "shortname": shortname,
                "id": tactic["id"],
                "name": tactic["name"],
            }
        )

    return sorted(rows, key=lambda row: row["id"])


def search_by_tactic(
    shortname: str,
    limit: int = DEFAULT_LIMIT,
    include_subtechniques: bool = False,
) -> dict[str, Any]:
    
    index = get_index()
    key = shortname.strip().lower() if isinstance(shortname, str) else ""

    if key not in index["tactics"]:
        valid = ", ".join(sorted(index["tactics"]))
        raise MitreError(f"unknown tactic, valid tactics: {valid}")

    found = []

    for technique_id in sorted(index["techniques"]):
        entry = index["techniques"][technique_id]

        if key not in entry["tactics"]:
            continue

        if entry["is_subtechnique"] and not include_subtechniques:
            continue

        found.append(summarize(entry))

    return {
        "tactic": key,
        "total": len(found),
        "techniques": found[:clamp_limit(limit)],
    }


def name_rank(name: str, query: str) -> int:
    lowered = name.lower()

    if lowered == query:
        return 0

    if lowered.startswith(query):
        return 1

    return 2


def search_by_name(text: str, 
                   limit: int = DEFAULT_LIMIT
                   ) -> list[dict]:
    if not isinstance(text, str):
        return []

    query = sanitize_string(text, MAX_QUERY_CHARS).strip().lower()

    if not query:
        return []

    words = query.split()
    matches = []

    for entry in get_index()["techniques"].values():
        lowered = entry["name"].lower()

        if all(word in lowered for word in words):
            matches.append((name_rank(entry["name"], query), entry))

    matches.sort(key=lambda pair: (pair[0], pair[1]["id"]))

    return [summarize(entry) for _, entry in matches[:clamp_limit(limit)]]


# For Testings: arrash/bin/python -m app.rag.mitre_attack
# arrash is my local development environment.

if __name__ == "__main__":
    
    scan = lookup("t1595.002")
    assert scan is not None and scan["name"] == "Vulnerability Scanning"
    assert scan["parent"] == "T1595"
    assert lookup("T9999") is None and lookup(None) is None

    active = check_technique("T1595.002")
    assert active["status"] == "active"
    assert active["tactics"] == ["reconnaissance"]

    revoked = check_technique("t1066")
    assert revoked["status"] == "revoked"
    assert revoked["replacement"] == "T1027.005"

    assert check_technique("T9999")["status"] == "unknown"
    assert check_technique("hello")["status"] == "invalid_format"
    assert check_technique(["T1595"])["status"] == "invalid_format"

    recon = search_by_tactic("Reconnaissance", limit=3)
    assert recon["total"] >= 3 and len(recon["techniques"]) == 3
    assert search_by_name("scanning")[0]["id"].startswith("T1595")

    try:
        search_by_tactic("defense-evasion")
        raise AssertionError("old tactic name was accepted")
    
    except MitreError:
        pass

    count = len(get_index()["techniques"])
    print(f"Loaded {count} techniques. Self-check passed.")
