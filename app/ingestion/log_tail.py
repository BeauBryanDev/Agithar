from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from app.ingestion.nginx_parser import AccessLine, LineError, parse_line

MAX_LINES = 50000
ROTATED_SUFFIX = ".1"


class LogUnavailableError(Exception):
    # Fixed text, no path: it is shown to the model and the admin.
    pass


@dataclass
class LogWindow:
    # The requests of the asked hosts since the asked time, oldest first.
    lines: list[AccessLine] = field(default_factory=list)
    rejected: Counter = field(default_factory=Counter)
    # Oldest request time found in the bytes that were read (any host).
    oldest: float | None = None
    # True when the data reaches back to the start of the asked window.
    complete: bool = False
    # True when the whole log (and the rotated one, if used) was read, so
    # nothing older exists to read; False when the byte cap cut it short.
    reached_start: bool = False


def read_tail(path: Path, max_bytes: int) -> tuple[list[str], bool]:
    # The last max_bytes of a log as whole lines, and whether that reached
    # the start of the file. Never reads more than max_bytes.
    size = path.stat().st_size
    start = max(0, size - max_bytes)

    with path.open("rb") as handle:
        handle.seek(start)
        data = handle.read(max_bytes)

    pieces = data.decode("utf-8", "replace").split("\n")

    if start > 0:
        pieces = pieces[1:]

    # The last piece is empty or a half-written line: either way not a line.
    return pieces[:-1], start == 0


def parse_lines(lines: list[str]) -> tuple[list[AccessLine], Counter]:
    parsed: list[AccessLine] = []
    rejected: Counter = Counter()

    for raw in lines:
        try:
            parsed.append(parse_line(raw))

        except LineError as exc:
            rejected[str(exc)] += 1

    return parsed, rejected


def load_window(
    path: Path,
    hosts: set[str] | None,
    since: float,
    max_bytes: int,
) -> LogWindow:
    # hosts None means every host. The current file is read first; when it
    # does not reach back far enough, the rotated file (name.1, still plain
    # text for a day) is read as well, so a window across midnight works.
    try:
        lines, from_start = read_tail(path, max_bytes)

    except OSError:
        raise LogUnavailableError(
            "the web server log is missing or not readable by Agithar"
        ) from None

    parsed, rejected = parse_lines(lines)
    rotated = path.with_name(path.name + ROTATED_SUFFIX)
    oldest = min((p.timestamp for p in parsed), default=None)

    if from_start and (oldest is None or oldest > since) and rotated.exists():
        try:
            older, from_start = read_tail(rotated, max_bytes)

        except OSError:
            older, from_start = [], False

        before, more = parse_lines(older)
        parsed = before + parsed
        rejected += more
        oldest = min((p.timestamp for p in parsed), default=None)

    wanted = [
        p for p in parsed
        if p.timestamp >= since and (hosts is None or p.host in hosts)
    ]

    return LogWindow(
        lines=wanted[-MAX_LINES:],
        rejected=rejected,
        oldest=oldest,
        complete=oldest is not None and oldest <= since,
        reached_start=from_start,
    )
