import re

# The payload model learned "svg" as an XSS marker (<svg onload=...>), so
# every plain icon scores about 0.9. A request is skipped only when it is
# clearly a plain asset: GET or HEAD, a path of safe characters only, no
# segment starting with a dot (no "..", no hidden files), a known asset
# extension, and no query or a short version tag. Anything else is scored.
ASSET_METHODS = frozenset({"GET", "HEAD"})
MAX_TARGET_CHARS = 300
ASSET_PATH = re.compile(
    r"^(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}){0,8}"
    r"/[A-Za-z0-9_-][A-Za-z0-9_.-]{0,119}"
    r"\.(?:svg|png|jpe?g|webp|avif|gif|ico|bmp"
    r"|css|js|mjs|map|woff2?|ttf|otf|eot)$",
    re.IGNORECASE,
)
SAFE_QUERY = re.compile(
    r"^[A-Za-z0-9_-]{1,20}=[A-Za-z0-9._-]{1,40}"
    r"(?:&[A-Za-z0-9_-]{1,20}=[A-Za-z0-9._-]{1,40}){0,2}$"
)


def is_plain_asset(method: str | None, target: str | None) -> bool:
    if method not in ASSET_METHODS or not target:
        return False

    if len(target) > MAX_TARGET_CHARS:
        return False

    path, mark, query = target.partition("?")

    if ".." in path or not ASSET_PATH.match(path):
        return False

    if mark and not SAFE_QUERY.match(query):
        return False

    return True
