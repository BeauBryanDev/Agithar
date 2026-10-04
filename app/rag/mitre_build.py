
import re
from collections import defaultdict
from datetime import datetime, timezone

from app.security.sanitize import sanitize_string

MAX_TEXT_CHARS = 1500
MAX_NAME_CHARS = 200
MAX_LIST = 10
MAX_REVOKED_HOPS = 5
SOURCE_NAME = "mitre-attack"
CITATION = re.compile(r"\s*\(Citation: [^)]*\)")
MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
HTML_TAG = re.compile(r"</?code>")
SOFTWARE_TYPES = ("malware", "tool")


def attack_reference(obj: dict) -> tuple[str, str]:
    
    for reference in obj.get("external_references", []):
        if reference.get("source_name") == SOURCE_NAME:
            return reference.get("external_id", ""), reference.get("url", "")

    return "", ""


def is_live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def clean_text(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    text = CITATION.sub("", text)
    text = MARKDOWN_LINK.sub(r"\1", text)
    text = HTML_TAG.sub("", text)

    return sanitize_string(text, limit)


def build_tactics(objects: list[dict]) -> dict[str, dict]:
    tactics = {}

    for obj in objects:
        if obj["type"] != "x-mitre-tactic":
            continue

        tactic_id, _ = attack_reference(obj)
        tactics[obj["x_mitre_shortname"]] = {
            "id": tactic_id,
            "name": clean_text(obj["name"], 
                               MAX_NAME_CHARS
                               ),
        }

    return tactics


def live_relationships(objects: list[dict], kind: str) -> list[dict]:
    return [
        obj
        for obj in objects
        if obj["type"] == "relationship"
        and obj["relationship_type"] == kind
        and is_live(obj)
    ]


def count_uses(uses: list[dict], by_id: dict[str, dict]) -> dict[str, int]:
    # A group or tool that uses more techniques ranks higher in the lists.
    counts: dict[str, int] = defaultdict(int)

    for rel in uses:
        target = by_id.get(rel["target_ref"])

        if target and target["type"] == "attack-pattern" and is_live(target):
            counts[rel["source_ref"]] += 1

    return counts


def ranked_users(
    uses: list[dict],
    by_id: dict[str, dict],
    kinds: tuple[str, ...],
    counts: dict[str, int],
) -> dict[str, list[dict]]:
    found: dict[str, dict[str, dict]] = defaultdict(dict)

    for rel in uses:
        source = by_id.get(rel["source_ref"])

        if not source or source["type"] not in kinds or not is_live(source):
            continue

        source_id, _ = attack_reference(source)
        entry = {"id": source_id, "name": clean_text(source["name"], 120)}
        found[rel["target_ref"]][rel["source_ref"]] = entry

    result = {}

    for target, sources in found.items():
        ordered = sorted(
            sources,
            key=lambda ref: (-counts[ref], sources[ref]["name"]),
        )
        result[target] = [sources[ref] for ref in ordered]

    return result


def names_by_target(
    objects: list[dict], 
    by_id: dict[str, dict], 
    kind: str, 
    source_type: str
) -> dict[str, list[str]]:
    
    names: dict[str, list[str]] = defaultdict(list)

    for rel in live_relationships(objects, kind):
        source = by_id.get(rel["source_ref"])

        if source and source["type"] == source_type and is_live(source):
            names[rel["target_ref"]].append(clean_text(source["name"], 160))

    return {target: sorted(set(found)) for target, found in names.items()}


def build_techniques(objects: list[dict], 
                     tactics: dict
                     ) -> dict[str, dict]:
    
    by_id = {obj["id"]: obj for obj in objects}
    parents = {
        rel["source_ref"]: rel["target_ref"]
        for rel in live_relationships(objects, "subtechnique-of")
    }
    mitigations = names_by_target(
        objects, by_id, "mitigates", "course-of-action"
    )
    detections = names_by_target(
        objects, by_id, "detects", "x-mitre-detection-strategy"
    )
    uses = live_relationships(objects, "uses")
    counts = count_uses(uses, by_id)
    groups = ranked_users(uses, by_id, ("intrusion-set",), counts)
    software = ranked_users(uses, by_id, SOFTWARE_TYPES, counts)
    techniques = {}

    for obj in objects:
        if obj["type"] != "attack-pattern" or not is_live(obj):
            continue

        technique_id, url = attack_reference(obj)
        phases = obj.get("kill_chain_phases", [])
        parent = by_id.get(parents.get(obj["id"], ""))
        technique_groups = groups.get(obj["id"], [])
        technique_software = software.get(obj["id"], [])

        techniques[technique_id] = {
            "id": technique_id,
            "name": clean_text(obj["name"], MAX_NAME_CHARS),
            "description": clean_text(obj.get("description", "")),
            "tactics": [p["phase_name"] for p in phases],
            "platforms": obj.get("x_mitre_platforms", []),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": attack_reference(parent)[0] if parent else None,
            "url": url,
            "version": obj.get("x_mitre_version", ""),
            "mitigations": mitigations.get(obj["id"], [])[:MAX_LIST],
            "detections": detections.get(obj["id"], [])[:MAX_LIST],
            "group_count": len(technique_groups),
            "groups": technique_groups[:MAX_LIST],
            "software_count": len(technique_software),
            "software": technique_software[:MAX_LIST],
        }

    return techniques


def replacement_chain(start: str, 
                      replaced: dict[str, str], 
                      live: dict
                      ) -> str:
    
    current = start

    for _ in range(MAX_REVOKED_HOPS):
        current = replaced.get(current, "")

        if current in live:
            return current

    return ""


def build_revoked(objects: list[dict], 
                  techniques: dict
                  ) -> dict[str, dict]:
    
    by_id = {obj["id"]: obj for obj in objects}
    
    replaced = {
        rel["source_ref"]: rel["target_ref"]
        for rel in objects
        if rel["type"] == "relationship"
        and rel["relationship_type"] == "revoked-by"
    }
    live_stix = {
        obj["id"]: attack_reference(obj)[0]
        for obj in objects
        if obj["type"] == "attack-pattern" and is_live(obj)
    }
    revoked = {}

    for obj in objects:
        if obj["type"] != "attack-pattern" or not obj.get("revoked"):
            continue

        old_id, _ = attack_reference(obj)
        target = replacement_chain(obj["id"], 
                                   replaced, 
                                   live_stix
                                   )
        revoked[old_id] = {
            "name": clean_text(obj["name"], 
                               MAX_NAME_CHARS
                               ),
            "replaced_by": live_stix.get(target, ""),
        }

    return revoked


def build_meta(objects: list[dict], 
               count: int
               ) -> dict:
    
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    marking = next(o for o in objects if o["type"] == "marking-definition")

    return {
        "attack_version": collection.get("x_mitre_version", ""),
        "bundle_modified": collection.get("modified", ""),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "technique_count": count,
        "copyright": marking["definition"]["statement"],
    }


def build_index(objects: list[dict]) -> dict:
    
    tactics = build_tactics(objects)
    techniques = build_techniques(objects, tactics)

    return {
        "meta": build_meta(objects, len(techniques)),
        "tactics": tactics,
        "techniques": techniques,
        "revoked": build_revoked(objects, techniques),
    }
