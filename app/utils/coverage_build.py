from collections import Counter
from typing import Any

LEVEL_BLIND = 0
LEVEL_LOG_MISSING = 1
LEVEL_RULE_READY = 2
LEVEL_COVERED = 3
LEVEL_NAMES = {
    LEVEL_BLIND: "blind: no public rule and no sensor",
    LEVEL_LOG_MISSING: "rules exist but need a log that is not collected",
    LEVEL_RULE_READY: "rules exist for a log that is collected",
    LEVEL_COVERED: "watched by a live sensor",
}
LEVEL_COLORS = ("#e06666", "#f6b26b", "#ffe599", "#93c47d")
SCOPE_PLATFORM = "Linux"
HOST_PLATFORMS = ("linux", "web")
# The logs this server really keeps: the nginx access log and auth.log,
# which holds the sshd, sudo and PAM messages.
WEB_CATEGORY = "webserver"
AUTH_SERVICES = ("sshd", "auth", "sudo")
MAX_LOG_LABELS = 4
MAX_SAMPLE_RULES = 3
MAX_COMMENT_CHARS = 300
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
LAYER_NAME = "Agithar detection coverage"


def rule_is_usable(rule: dict[str, str]) -> bool:
    if rule["platform"] == "web" and rule["category"] == WEB_CATEGORY:
        return True

    return rule["product"] == "linux" and rule["service"] in AUTH_SERVICES


def log_label(rule: dict[str, str]) -> str:
    parts = []

    for key in ("product", "category", "service"):
        if rule[key]:
            parts.append(rule[key])

    return " ".join(parts) or rule["platform"]


def group_rules(rules: list[dict[str, str]]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}

    for rule in rules:
        grouped.setdefault(rule["technique"], []).append(rule)

    return grouped


def top_labels(rules: list[dict[str, str]]) -> list[str]:
    counts = Counter(log_label(rule) for rule in rules)

    return [label for label, _ in counts.most_common(MAX_LOG_LABELS)]


def level_of(sensors: list[str], usable: int, total: int) -> int:
    if sensors:
        return LEVEL_COVERED

    if usable:
        return LEVEL_RULE_READY

    return LEVEL_LOG_MISSING if total else LEVEL_BLIND


def sample_rules(usable: list[dict], other: list[dict]) -> list[dict]:
    samples = []

    for rule in (*usable, *other)[:MAX_SAMPLE_RULES]:
        samples.append({"rule_id": rule["rule_id"], "title": rule["title"]})

    return samples


def build_row(
    entry: dict[str, Any],
    rules: list[dict[str, str]],
    sensors: list[str],
    offline_sensors: list[str],
    incidents: int,
) -> dict[str, Any]:
    usable = [rule for rule in rules if rule_is_usable(rule)]
    other = [rule for rule in rules if not rule_is_usable(rule)]

    return {
        "technique": entry["id"],
        "name": entry["name"],
        "tactics": list(entry["tactics"]),
        "parent": entry["parent"],
        "level": level_of(sensors, len(usable), len(rules)),
        "rules": len(rules),
        "usable_rules": len(usable),
        "usable_logs": top_labels(usable),
        "missing_logs": top_labels(other),
        "sensors": sensors,
        "offline_sensors": offline_sensors,
        "incidents": incidents,
        "threat_groups": int(entry.get("group_count") or 0),
        "sample_rules": sample_rules(usable, other),
    }


def host_rules(rules: list[dict[str, str]]) -> bool:
    # A cloud or network rule alone does not make a technique ours.
    return any(rule["platform"] in HOST_PLATFORMS for rule in rules)


def in_scope(entry: dict[str, Any], has_signal: bool) -> bool:
    # Linux techniques, plus any other technique we have a host rule, a
    # sensor or an incident for (scanning, for example, is PRE).
    return SCOPE_PLATFORM in entry["platforms"] or has_signal


def build_matrix(
    techniques: dict[str, dict[str, Any]],
    rules: list[dict[str, str]],
    live_sensors: dict[str, list[str]],
    offline_sensors: dict[str, list[str]],
    seen: dict[str, int],
) -> list[dict[str, Any]]:
    grouped = group_rules(rules)
    rows = []

    for technique_id in sorted(techniques):
        entry = techniques[technique_id]
        own_rules = grouped.get(technique_id, [])
        sensors = live_sensors.get(technique_id, [])
        offline = offline_sensors.get(technique_id, [])
        incidents = seen.get(technique_id, 0)
        has_signal = bool(
            sensors or offline or incidents or host_rules(own_rules)
        )

        if in_scope(entry, has_signal):
            rows.append(
                build_row(entry, own_rules, sensors, offline, incidents)
            )

    return rows


def gap_order(row: dict[str, Any]) -> tuple[int, int, str]:
    # Seen in our own incidents first, then used by the most threat groups.
    return (-row["incidents"], -row["threat_groups"], row["technique"])


def top_gaps(rows: list[dict], level: int, limit: int) -> list[dict]:
    chosen = [row for row in rows if row["level"] == level]

    return sorted(chosen, key=gap_order)[:limit]


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row["level"] for row in rows)
    levels = []

    for level, meaning in LEVEL_NAMES.items():
        levels.append(
            {
                "level": level,
                "meaning": meaning,
                "techniques": counts.get(level, 0),
            }
        )

    return {
        "techniques_in_scope": len(rows),
        "levels": levels,
        "seen_in_incidents": sum(1 for row in rows if row["incidents"]),
    }


def layer_comment(row: dict[str, Any]) -> str:
    parts = [LEVEL_NAMES[row["level"]]]

    if row["rules"]:
        parts.append(
            f"{row['rules']} Sigma rules, {row['usable_rules']} usable "
            "with the collected logs"
        )

    if row["sensors"]:
        parts.append("sensors: " + ", ".join(row["sensors"]))

    if row["missing_logs"]:
        parts.append("logs needed: " + ", ".join(row["missing_logs"]))

    if row["incidents"]:
        parts.append(f"seen in {row['incidents']} incidents")

    return "; ".join(parts)[:MAX_COMMENT_CHARS]


def legend() -> list[dict[str, str]]:
    items = []

    for level, meaning in LEVEL_NAMES.items():
        items.append({"label": meaning, "color": LEVEL_COLORS[level]})

    return items


def build_layer(
    rows: list[dict[str, Any]], attack_version: str, description: str
) -> dict[str, Any]:
    parents = {row["parent"] for row in rows if row["parent"]}
    techniques = []

    for row in rows:
        techniques.append(
            {
                "techniqueID": row["technique"],
                "score": row["level"],
                "comment": layer_comment(row),
                "showSubtechniques": row["technique"] in parents,
            }
        )

    return {
        "name": LAYER_NAME,
        "versions": {
            "attack": attack_version.split(".", 1)[0],
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": list(LEVEL_COLORS),
            "minValue": LEVEL_BLIND,
            "maxValue": LEVEL_COVERED,
        },
        "legendItems": legend(),
    }
