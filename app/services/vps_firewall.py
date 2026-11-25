
import asyncio
import ipaddress
import re
import time
from pathlib import Path
from typing import Any

import boto3
import httpx
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.sanitize import sanitize_string
from app.services.net_service import collect_listening_ports

# Read-only by design: two config files and two AWS Describe calls. No
# subprocess, no sudo, no root-only file, and no call that changes a rule.

logger = get_logger("services.vps_firewall")

UFW_CONF = Path("/etc/ufw/ufw.conf")
UFW_DEFAULTS = Path("/etc/default/ufw")
MAX_CONFIG_BYTES = 65536
IMDS_BASE = "http://169.254.169.254/latest"
IMDS_TIMEOUT_SECONDS = 1.0
INSTANCE_PATTERN = re.compile(r"^i-[0-9a-f]{8,17}$")
CACHE_SECONDS = 60
MAX_RULES = 100
MAX_NAME_CHARS = 64
WEB_PORTS = (80, 443)
SSH_PORT = 22
POLICIES = {
    "DROP": "deny",
    "REJECT": "reject",
    "ACCEPT": "allow",
}
BOTO_CONFIG = Config(
    connect_timeout=3,
    read_timeout=5,
    retries={"max_attempts": 2, "mode": "standard"},
)

_cache: tuple[float, dict[str, Any]] | None = None
_lock = asyncio.Lock()


def read_config(path: Path) -> dict[str, str] | None:
    try:
        with path.open("rb") as handle:
            text = handle.read(MAX_CONFIG_BYTES).decode("utf-8", "replace")

    except OSError:
        return None

    values = {}

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")

    return values


def ufw_state() -> dict[str, Any]:
    conf = read_config(UFW_CONF) or {}
    defaults = read_config(UFW_DEFAULTS) or {}
    enabled = conf.get("ENABLED", "").lower()
    policy = defaults.get("DEFAULT_INPUT_POLICY", "").upper()

    return {
        "enabled": {"yes": True, "no": False}.get(enabled),
        "default_incoming": POLICIES.get(policy, "unknown"),
        "note": (
            "read from the ufw config files only; the rule list and the "
            "live kernel state need root and are not read"
        ),
    }


async def instance_id() -> tuple[str | None, str | None]:
    # IMDSv2 first, then the AWS_INSTANCE_ID setting.
    try:
        async with httpx.AsyncClient(
            timeout=IMDS_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            token = await client.put(
                f"{IMDS_BASE}/api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            )
            token.raise_for_status()
            reply = await client.get(
                f"{IMDS_BASE}/meta-data/instance-id",
                headers={"X-aws-ec2-metadata-token": token.text},
            )
            reply.raise_for_status()

        if INSTANCE_PATTERN.match(reply.text.strip()):
            return reply.text.strip(), "imds"

    except httpx.HTTPError:
        pass

    fallback = get_settings().aws_instance_id

    return (fallback, "setting") if fallback else (None, None)


def rule_rows(permission: dict[str, Any]) -> list[dict[str, Any]]:
    proto = str(permission.get("IpProtocol", ""))
    base = {
        "proto": "all" if proto == "-1" else proto,
        "from_port": permission.get("FromPort"),
        "to_port": permission.get("ToPort"),
    }
    sources = []

    for entry in permission.get("IpRanges", []):
        sources.append(entry.get("CidrIp"))

    for entry in permission.get("Ipv6Ranges", []):
        sources.append(entry.get("CidrIpv6"))

    for entry in permission.get("UserIdGroupPairs", []):
        sources.append(f"group:{entry.get('GroupId')}")

    for entry in permission.get("PrefixListIds", []):
        sources.append(f"prefix-list:{entry.get('PrefixListId')}")

    rows = []

    for source in sources:
        if isinstance(source, str):
            rows.append({**base, "source": sanitize_string(source, 64)})

    return rows


def fetch_security_groups(instance: str) -> dict[str, Any]:
    region = get_settings().aws_region
    ec2 = boto3.client("ec2", region_name=region, config=BOTO_CONFIG)
    reply = ec2.describe_instances(InstanceIds=[instance])
    group_ids = []

    for reservation in reply.get("Reservations", []):
        for item in reservation.get("Instances", []):
            for group in item.get("SecurityGroups", []):
                group_ids.append(group["GroupId"])

    groups = []
    rules = []

    if group_ids:
        described = ec2.describe_security_groups(GroupIds=group_ids)
        groups = described.get("SecurityGroups", [])

    for group in groups:
        for permission in group.get("IpPermissions", []):
            rules.extend(rule_rows(permission))

    return {
        "available": True,
        "groups": [
            {
                "id": group.get("GroupId"),
                "name": sanitize_string(
                    str(group.get("GroupName", "")), MAX_NAME_CHARS
                ),
            }
            for group in groups
        ],
        "rules": rules[:MAX_RULES],
    }


async def security_group_state() -> dict[str, Any]:
    instance, origin = await instance_id()

    if instance is None:
        return {"available": False, "reason": "instance id unknown"}

    try:
        state = await asyncio.to_thread(fetch_security_groups, instance)

    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "unknown")
        logger.warning("security group read failed: %s", code)
        return {"available": False, "reason": f"aws refused: {code}"}

    except BotoCoreError as exc:
        logger.warning("security group read failed: %s", type(exc).__name__)
        return {"available": False, "reason": "aws unreachable"}

    state["instance_id_source"] = origin

    return state


def covers(rule: dict[str, Any], port: int, proto: str) -> bool:
    if rule["proto"] == "all":
        return True

    low = rule["from_port"]
    high = rule["to_port"]

    if rule["proto"] != proto or low is None or high is None:
        return False

    return low <= port <= high


def network_of(source: str) -> Any:
    try:
        return ipaddress.ip_network(source, strict=False)
    except ValueError:
        return None


def is_world(source: str) -> bool:
    net = network_of(source)

    return net is not None and net.prefixlen == 0


def finding(category: str, severity: str, text: str) -> dict[str, str]:
    return {
        "category": category,
        "severity": severity,
        "description": text,
    }


def rule_findings(rules: list[dict[str, Any]]) -> list[dict[str, str]]:
    found = []
    ssh_wide = False
    web_world = False

    for rule in rules:
        source = rule["source"]
        net = network_of(source)

        if rule["proto"] == "all" and is_world(source):
            found.append(finding(
                "rule_gap", "high",
                "the security group allows all traffic from the internet",
            ))

        if covers(rule, SSH_PORT, "tcp") and net is not None:
            if net.prefixlen < net.max_prefixlen:
                ssh_wide = True

        for port in WEB_PORTS:
            if covers(rule, port, "tcp") and is_world(source):
                web_world = True

    if ssh_wide:
        found.append(finding(
            "rule_gap", "medium",
            "ssh is allowed from a range wider than one address",
        ))

    if web_world:
        found.append(finding(
            "rule_gap", "low",
            "ports 80/443 are open to the whole internet, not only to "
            "Cloudflare, so the origin can be reached directly",
        ))

    return found


def mark_public(
    listening: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[dict[str, str]]:
    found = []

    for row in listening:
        open_rules = [r for r in rules if covers(r, row["port"], row["proto"])]
        world = any(is_world(rule["source"]) for rule in open_rules)
        row["public"] = row["exposure"] != "loopback" and world

        if row["public"] and row["port"] not in (*WEB_PORTS, SSH_PORT):
            found.append(finding(
                "posture_drift", "medium",
                f"{row['proto']} port {row['port']} listens on all "
                "interfaces and the security group opens it to the internet",
            ))

    return found


def host_findings(ufw: dict[str, Any]) -> list[dict[str, str]]:
    if ufw["enabled"] is False:
        return [finding("posture_drift", "medium", "ufw is disabled")]

    if ufw["default_incoming"] == "allow":
        return [finding(
            "posture_drift", "medium",
            "ufw default incoming policy is allow",
        )]

    return []


async def build_snapshot() -> dict[str, Any]:
    ufw = await asyncio.to_thread(ufw_state)
    listening = await asyncio.to_thread(collect_listening_ports)
    group = await security_group_state()
    rules = group.get("rules", [])
    findings = host_findings(ufw)

    if group["available"]:
        findings.extend(rule_findings(rules))
        findings.extend(mark_public(listening, rules))

    return {
        "host_firewall": ufw,
        "security_group": group,
        "listening": listening,
        "findings": findings,
        "generated_at": int(time.time()),
    }


async def get_firewall_snapshot() -> dict[str, Any]:
    global _cache

    async with _lock:
        now = time.monotonic()

        if _cache is not None and _cache[0] > now:
            return _cache[1]

        snapshot = await build_snapshot()
        _cache = (now + CACHE_SECONDS, snapshot)

        return snapshot
