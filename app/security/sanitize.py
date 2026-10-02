
import math
import unicodedata
from typing import Any

MAX_DETAIL_KEYS = 32
MAX_KEY_CHARS = 128
MAX_STRING_CHARS = 2048
MAX_LIST_ITEMS = 50
MAX_NESTING_DEPTH = 3

TRUNCATION_MARKER = "...[truncated]"
NORMALIZE_SLACK = 4
SPACE_CHARS = frozenset("\t\n\r\x0b\x0c")
SPACE_CATEGORIES = frozenset({"Zl", "Zp"})
DROP_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


def strip_control_chars(value: str) -> str:
    kept: list[str] = []

    for char in value:
        category = unicodedata.category(char)

        if char in SPACE_CHARS or category in SPACE_CATEGORIES:
            kept.append(" ")

        elif category not in DROP_CATEGORIES:
            kept.append(char)

    return "".join(kept)


def sanitize_string(value: str, 
                    max_chars: int = MAX_STRING_CHARS
                    ) -> str:

    cleaned = value[:max_chars * NORMALIZE_SLACK]
    cleaned = unicodedata.normalize("NFKC", cleaned)
    cleaned = strip_control_chars(cleaned)

    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars] + TRUNCATION_MARKER

    return cleaned


def sanitize_value(value: Any, depth: int) -> Any:
    if depth > MAX_NESTING_DEPTH:
        return None

    if isinstance(value, bool) or value is None:
        return value

    if isinstance(value, float) and not math.isfinite(value):
        return None

    if isinstance(value, (int, float)):
        return value

    if isinstance(value, str):
        return sanitize_string(value)

    if isinstance(value, dict):
        return sanitize_detail(value, depth + 1)

    if isinstance(value, list):
        items = value[:MAX_LIST_ITEMS]

        return [sanitize_value(item, depth + 1) for item in items]

    return None


def sanitize_detail(detail: dict[str, Any], 
                    depth: int = 0
                    ) -> dict[str, Any]:
    
    if not isinstance(detail, dict):
        raise ValueError("detail must be an object")

    cleaned: dict[str, Any] = {}

    for index, (key, value) in enumerate(detail.items()):
        if index >= MAX_DETAIL_KEYS:
            break

        if not isinstance(key, str):
            continue

        safe_key = sanitize_string(key, MAX_KEY_CHARS)
        cleaned[safe_key] = sanitize_value(value, depth)

    return cleaned

