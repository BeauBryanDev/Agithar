import asyncio
import json
import os
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from app.core.logging import get_logger

logger = get_logger("ingestion.tailer")

CHUNK_BYTES = 65536
MAX_LINE_BYTES = 65536
MAX_LINES_PER_PASS = 5000
POLL_SECONDS = 1.0
ROTATED_SUFFIX = ".1"

Handler = Callable[[list[str], bool], Awaitable[None]]


@dataclass
class TailState:
    device: int
    inode: int
    offset: int


class LogTailer:
    # Follows one log file that logrotate replaces with a NEW file (create
    # mode). The old file is read to its end before the new one is opened,
    # so no line is lost at rotation. Only whole lines are returned.

    def __init__(
        self,
        path: Path,
        state_path: Path | None = None,
        max_lines: int = MAX_LINES_PER_PASS,
    ) -> None:
        self.path = path
        self.state_path = state_path
        self.max_lines = max_lines
        self._file: BinaryIO | None = None
        self._ident: tuple[int, int] | None = None
        self._offset = 0
        self._buffer = b""
        self._skipping = False
        self._started = False
        self._saved: TailState | None = None
        self._open_failed = False

    def load_state(self) -> TailState | None:
        if self.state_path is None or not self.state_path.exists():
            return None

        try:
            data = json.loads(self.state_path.read_text())

            return TailState(
                int(data["device"]), 
                int(data["inode"]), 
                int(data["offset"])
            )

        except (OSError, ValueError, KeyError, TypeError):
            logger.error("tail state unreadable, starting at the end")

            return None

    def commit(self) -> None:
        # Call after the returned lines were handled (at-least-once).
        if self.state_path is None or self._ident is None:
            return

        state = TailState(self._ident[0], self._ident[1], self._offset)

        if state == self._saved:
            return

        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(dir=self.state_path.parent)

        with os.fdopen(fd, "w") as handle:
            json.dump(state.__dict__, handle)

        os.chmod(name, 0o600)
        os.replace(name, self.state_path)
        self._saved = state

    def open_at(self, path: Path, offset: int) -> None:
        stat = path.stat()
        file = path.open("rb")
        file.seek(offset)
        self._close_file()
        self._file = file
        self._ident = (stat.st_dev, stat.st_ino)
        self._offset = offset
        self._buffer = b""
        self._skipping = False

    def _close_file(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def close(self) -> None:
        self._close_file()

    def start(self) -> None:
        self._started = True

        try:
            stat = self.path.stat()

        except OSError:
            return

        state = self.load_state()
        self._saved = state

        if state is None:
            # First run: only lines written from now on are of interest.
            self.open_at(self.path, stat.st_size)

        elif (state.device, state.inode) == (stat.st_dev, stat.st_ino):
            start = state.offset if state.offset <= stat.st_size else 0
            self.open_at(self.path, start)

        else:
            self.resume_rotated(state)

    def resume_rotated(self, state: TailState) -> None:
        # The file was rotated while we were down: the old one is now
        # path.1 (still plain text for a day, thanks to delaycompress).
        old = self.path.with_name(self.path.name + ROTATED_SUFFIX)

        try:
            stat = old.stat()

            if (stat.st_dev, stat.st_ino) == (state.device, state.inode):
                self.open_at(old, min(state.offset, stat.st_size))
                return

        except OSError:
            pass

        logger.warning("lines written while down are lost (rotated away)")
        self.open_at(self.path, 0)

    def take_lines(self, limit: int) -> list[str]:
        lines: list[str] = []

        while len(lines) < limit:
            if self._skipping:
                cut = self._buffer.find(b"\n")

                if cut < 0:
                    self._offset += len(self._buffer)
                    self._buffer = b""
                    break

                self._offset += cut + 1
                self._buffer = self._buffer[cut + 1:]
                self._skipping = False

            cut = self._buffer.find(b"\n")

            if cut < 0:
                if len(self._buffer) > MAX_LINE_BYTES:
                    self._skipping = True
                    continue

                break

            raw = self._buffer[:cut]
            self._offset += cut + 1
            self._buffer = self._buffer[cut + 1:]
            lines.append(raw.decode("utf-8", "replace"))

        return lines

    def drain(self, limit: int) -> tuple[list[str], bool]:
        # Returns the lines and whether the open file was read to its end.
        lines = self.take_lines(limit)

        while len(lines) < limit and self._file is not None:
            chunk = self._file.read(CHUNK_BYTES)

            if not chunk:
                return lines, True

            self._buffer += chunk
            lines += self.take_lines(limit - len(lines))

        return lines, False

    def read(self) -> list[str]:
        if not self._started:
            self.start()

        if self._file is None:
            try:
                self.open_at(self.path, 0)
                self._open_failed = False

            except OSError as exc:
                # One message per failure streak, not one per second.
                if not self._open_failed:
                    logger.error("log not readable: %s", type(exc).__name__)
                    self._open_failed = True

                return []

        try:
            stat = self.path.stat()

        except OSError:
            stat = None

        ident = None if stat is None else (stat.st_dev, stat.st_ino)

        if stat is not None and ident == self._ident:
            if stat.st_size < self._offset:
                logger.warning("log file was truncated, reading from start")
                self.open_at(self.path, 0)

        lines, at_end = self.drain(self.max_lines)

        # A new file replaced the old one: switch once the old one is read
        # to its end. A half-written last line of the old file is dropped.
        if ident is not None and ident != self._ident and at_end:
            self.open_at(self.path, 0)

        return lines


async def follow(
    tailer: LogTailer,
    handle: Handler,
    stop: asyncio.Event,
    poll_seconds: float = POLL_SECONDS,
) -> None:
    # handle(lines, idle): idle is True when nothing new arrived, which lets
    # the caller flush time-based state.
    try:
        while not stop.is_set():
            try:
                lines = await asyncio.to_thread(tailer.read)

            except OSError as exc:
                logger.error("log read failed: %s", type(exc).__name__)
                lines = []

            await handle(lines, not lines)

            if lines:
                await asyncio.to_thread(tailer.commit)
                continue

            try:
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)

            except asyncio.TimeoutError:
                pass

    finally:
        tailer.close()
