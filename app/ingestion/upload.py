
import os
import csv
import io
import ipaddress
import re
from datetime import datetime

from app.ingestion.nginx_parser import (
    MAX_AGENT_CHARS,
    MAX_TARGET_CHARS,
    MIN_EPOCH,
    AccessLine,
    LineError,
    parse_line,
)
from app.security.sanitize import sanitize_string

# What an uploaded file may be. Anything else is refused BEFORE it is parsed:
# the file is only ever read as text, never executed, unpacked, imported or
# written to disk.
ALLOWED_EXTENSIONS = (".log", ".txt", ".csv")
MAX_LINE_CHARS = 16384
SNIFF_BYTES = 8192
SNIFF_LINES = 60
RECOGNISED_SHARE = 0.5
MAX_BAD_TEXT_SHARE = 0.02
CSV_FIELD_LIMIT = 65536
MIN_COLUMN_SHARE = 0.9
MAX_DELIMITER_COLUMNS = 200

# Files that start with these bytes are not text logs.
FORBIDDEN_START = (
    (b"\xd4\xc3\xb2\xa1", "packet capture"),
    (b"\xa1\xb2\xc3\xd4", "packet capture"),
    (b"\x0a\x0d\x0d\x0a", "packet capture"),
    (b"\x4d\x3c\xb2\xa1", "packet capture"),
    (b"\xa1\xb2\x3c\x4d", "packet capture"),
    (b"\x1f\x8b", "archive"),
    (b"PK\x03\x04", "archive"),
    (b"PK\x05\x06", "archive"),
    (b"BZh", "archive"),
    (b"\xfd7zXZ", "archive"),
    (b"7z\xbc\xaf", "archive"),
    (b"Rar!", "archive"),
    (b"MZ", "program"),
    (b"\x7fELF", "program"),
    (b"\xca\xfe\xba\xbe", "program"),
    (b"\xcf\xfa\xed\xfe", "program"),
    (b"\xfe\xed\xfa\xce", "program"),
    (b"#\x21", "script"),
    (b"<?php", "script"),
    (b"%PDF", "document"),
    (b"\xd0\xcf\x11\xe0", "document"),
    (b"{\\rtf", "document"),
)
FORBIDDEN_TEXT_START = (b"<", b"%!PS")

LOG_LINE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]\s]+ [+-][0-9]{4})\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}) (?:[0-9]+|-)'
    r'(?: "(?:[^"\\]|\\.)*" "(?P<agent>(?:[^"\\]|\\.)*)")?\s*$'
)
METHOD = re.compile(r"^[A-Z]{3,10}$")
EVENT_LINE = re.compile(r"^E[0-9]{1,2}(\s+E[0-9]{1,2})*$")

IP_COLUMNS = ("source ip", "src ip")
DST_IP_COLUMNS = ("destination ip", "dst ip")


class UploadRejected(Exception):
    # `reason` is one of a few fixed phrases; `status` is the HTTP code.
    def __init__(self, 
                 reason: str, 
                 status: int = 422
                 ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


def safe_name(raw: str) -> str:
    # The name is only displayed. Directory parts are dropped; it is never
    # used to open, create or name a file.
    base = re.split(r"[\\/]", raw)[-1]

    return sanitize_string(base, 120) or "upload"


def check_extension(name: str) -> None:
    if not name.lower().endswith(ALLOWED_EXTENSIONS):
        raise UploadRejected(
            "Unsupported file type. Use .log, .txt or .csv.", 415
        )


def check_content(data: bytes) -> None:
    head = data[:SNIFF_BYTES]

    if not head.strip():
        raise UploadRejected("The file is empty.")

    for magic, label in FORBIDDEN_START:
        if head.startswith(magic):
            raise UploadRejected(
                f"That is not a text file ({label}).", 415
            )

    if b"\x00" in head:
        raise UploadRejected("That is not a text file (binary data).", 415)

    if head.lstrip().lower().startswith(FORBIDDEN_TEXT_START):
        raise UploadRejected(
            "That looks like markup or a document, not a log.", 415
        )

    bad = head.decode("utf-8", errors="replace").count("�")

    if bad / max(len(head), 1) > MAX_BAD_TEXT_SHARE:
        raise UploadRejected("That is not UTF-8 text.", 415)


def split_lines(data: bytes, 
                max_lines: int
                ) -> tuple[list[str], bool]:
    # Whole lines, cut at the cap. NUL bytes are removed; overlong lines are
    # kept truncated so the caller can count them as unreadable.
    text = data.decode("utf-8", errors="replace").replace("\x00", "")
    lines = []

    for raw in text.splitlines():
        if not raw.strip():
            continue

        if len(lines) >= max_lines:
            return lines, True

        lines.append(raw)

    return lines, False


def normalize_ip(text: str) -> str | None:
    try:
        ip = ipaddress.ip_address(text.strip())

    except ValueError:
        return None

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return str(ip.ipv4_mapped)

    return str(ip)


def parse_log_time(text: str) -> float | None:
    try:
        moment = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")

    except ValueError:
        return None

    epoch = moment.timestamp()

    return epoch if epoch >= MIN_EPOCH else None


def parse_combined(line: str) -> AccessLine | None:
    match = LOG_LINE.match(line)

    if match is None:
        return None

    ip = normalize_ip(match["ip"])
    stamp = parse_log_time(match["time"])

    if ip is None or stamp is None:
        return None

    parts = match["request"].split(" ")
    valid = len(parts) >= 2 and METHOD.match(parts[0]) is not None
    target = parts[1][:MAX_TARGET_CHARS] if valid else None
    agent = sanitize_string(match["agent"] or "", MAX_AGENT_CHARS)

    return AccessLine(
        client_ip=ip,
        via_cloudflare=False,
        forged_cf_header=False,
        timestamp=stamp,
        host="",
        method=parts[0] if valid else None,
        target=target,
        status=int(match["status"]),
        user_agent=agent,
        valid_request=valid,
    )


def parse_access_line(line: str) -> AccessLine | None:
    # Our own nginx format first, then the common Apache and nginx format.
    if len(line) > MAX_LINE_CHARS:
        return None

    try:
        return parse_line(line)

    except LineError:
        return parse_combined(line)


def share(lines: list[str], test) -> float:
    sample = lines[:SNIFF_LINES]

    return sum(1 for line in sample if test(line)) / max(len(sample), 1)


def normalize_header(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip()).lower()


def pick_delimiter(header: str) -> str:
    best = max(",;\t", key=lambda d: header.count(d))

    return best if header.count(best) > 0 else ","


def detect_kind(lines: list[str],
                known_columns: set[str]
                ) -> str:
    
    first = lines[0] if lines else ""
    
    columns = {normalize_header(c) for c in first.split(pick_delimiter(first))}

    if len(columns & known_columns) >= 20:
        return "flow_csv"

    if share(lines, lambda l: parse_access_line(l) is not None) >= RECOGNISED_SHARE:
        return "access_log"

    if share(lines, lambda l: EVENT_LINE.match(l.strip()) is not None) >= RECOGNISED_SHARE:
        return "event_ids"

    raise UploadRejected(
        "Could not recognise the content. Expected an nginx or Apache "
        "access log, event ids (E5 E22 ...) or a CIC-IDS flow CSV."
    )


def read_flow_rows_unsafe(
    lines: list[str], 
    needed: dict[str, str], 
    max_rows: int
):
    # needed: lower-case column name -> canonical name. Yields
    # (row number, features, context); a bad row yields (number, None, None).
    csv.field_size_limit(CSV_FIELD_LIMIT)
    delimiter = pick_delimiter(lines[0])
    reader = csv.reader(io.StringIO("\n".join(lines)),
                        delimiter=delimiter)
    header = next(reader, [])

    if len(header) > MAX_DELIMITER_COLUMNS:
        raise UploadRejected("The CSV has too many columns.")

    names = [normalize_header(h) for h in header]
    index = {n: i for i, n in enumerate(names)}
    wanted = {low: index[low] for low in needed if low in index}
    context_idx = {
        key: next((index[c] for c in cols if c in index), None)
        for key, cols in (("src", IP_COLUMNS), ("dst", DST_IP_COLUMNS))
    }
    label_idx = index.get("label")
    port_idx = index.get("destination port")

    for number, row in enumerate(reader, start=1):
        if number > max_rows:
            return

        try:
            features = {
                needed[low]: float(row[i]) for low, i in wanted.items()
            }

        except (ValueError, IndexError):
            yield number, None, None
            continue

        context = {"src": None, "dst": None, "label": None, "port": None}

        for key, idx in context_idx.items():
            if idx is not None and idx < len(row):
                context[key] = normalize_ip(row[idx])

        if label_idx is not None and label_idx < len(row):
            context["label"] = sanitize_string(row[label_idx], 40)

        if port_idx is not None and port_idx < len(row):
            context["port"] = features.get("Destination Port")

        yield number, features, context


def read_flow_rows(lines: list[str], needed: dict[str, str], max_rows: int):
    # A malformed or hostile CSV must end as a clean rejection, never a 500.
    try:
        yield from read_flow_rows_unsafe(lines, needed, max_rows)

    except csv.Error:
        raise UploadRejected("The CSV could not be read.") from None


def header_columns(lines: list[str]) -> set[str]:
    first = lines[0] if lines else ""

    return {normalize_header(c) for c in first.split(pick_delimiter(first))}
