import json
import logging
import re
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from app.core.config import get_settings

LOGGER_NAME = "agithar"
LOG_FILE_NAME = "agithar.log"
LOG_DIR_MODE = 0o750
MAX_LOG_BYTES = 10 * 1024 * 1024
BACKUP_COUNT = 5
MAX_MESSAGE_CHARS = 4096
MASK = "[REDACTED]"
CONSOLE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"

SENSITIVE_KEYS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
)

JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"
)
HF_TOKEN_PATTERN = re.compile(r"\bhf_[A-Za-z0-9]{10,}")
BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
KEY_VALUE_PATTERN = re.compile(
    r"(?i)([\w-]*(?:password|passwd|pwd|token|secret|api[_-]?key"
    r"|authorization))(\"?\s*[=:]\s*\"?)([^\s&,;\"']+)"
)
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
STANDARD_ATTRS = frozenset(vars(logging.makeLogRecord({})))
STANDARD_ATTRS = STANDARD_ATTRS | {"message", "asctime"}


def mask_key_value(match: re.Match) -> str:
    return f"{match.group(1)}{match.group(2)}{MASK}"


def escape_control_char(match: re.Match) -> str:
    return match.group(0).encode("unicode_escape").decode("ascii")


def redact_text(text: str) -> str:
    text = JWT_PATTERN.sub(MASK, text)
    text = HF_TOKEN_PATTERN.sub(MASK, text)
    text = BEARER_PATTERN.sub(f"Bearer {MASK}", text)
    
    return KEY_VALUE_PATTERN.sub(mask_key_value, text)


def truncate_text(text: str) -> str:
    if len(text) <= MAX_MESSAGE_CHARS:
        return text
    
    return text[:MAX_MESSAGE_CHARS] + "...[truncated]"


def escape_control_chars(text: str) -> str:
    return CONTROL_CHAR_PATTERN.sub(escape_control_char, text)


def clean_extra(key: str, value: Any) -> Any:
    if any(word in key.lower() for word in SENSITIVE_KEYS):
        return MASK
    
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    
    return truncate_text(redact_text(str(value)))


def iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = truncate_text(redact_text(record.getMessage()))
        record.msg = message
        record.args = ()
        return True


class ConsoleFormatter(logging.Formatter):
    def formatMessage(self, record: logging.LogRecord) -> str:
        record.message = escape_control_chars(record.message)
        return super().formatMessage(record)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "timestamp": iso_utc(record.created),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for key, value in record.__dict__.items():
            if key not in STANDARD_ATTRS:
                entry[key] = clean_extra(key, value)

        if record.exc_info:
            trace = self.formatException(record.exc_info)
            entry["exception"] = truncate_text(redact_text(trace))

        return json.dumps(entry, ensure_ascii=True)


def build_console_handler() -> logging.Handler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ConsoleFormatter(CONSOLE_FORMAT))
    handler.addFilter(RedactFilter())
    
    return handler


def build_file_handler(log_dir: Path) -> logging.Handler:
    log_dir.mkdir(mode=LOG_DIR_MODE, parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        log_dir / LOG_FILE_NAME,
        maxBytes=MAX_LOG_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactFilter())
    
    return handler


def configure_logging() -> logging.Logger:
    app_logger = logging.getLogger(LOGGER_NAME)
    if app_logger.handlers:
        return app_logger

    settings = get_settings()
    app_logger.setLevel(settings.log_level)
    app_logger.propagate = False
    app_logger.addHandler(build_console_handler())

    try:
        app_logger.addHandler(build_file_handler(settings.log_dir))
        
    except OSError as exc:
        app_logger.error("file logging disabled: %s", exc)

    return app_logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


logger = configure_logging()
