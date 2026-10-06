from typing import Any, Literal

from app.core.config import get_settings


def shop_names() -> tuple[str, ...]:
    return tuple(get_settings().shop_map)


# Built once from the settings: the model can only choose these names.
ShopName = Literal[(*shop_names(), "all")]


def hosts_for(shop: str) -> set[str]:
    mapping = get_settings().shop_map

    if shop == "all":
        return set(mapping.values())

    return {mapping[shop]}


def shop_of_host() -> dict[str, str]:
    # host -> shop name
    return {host: name for name, host in get_settings().shop_map.items()}


def shop_of_evidence(evidence: list[dict[str, Any]] | None) -> str:
    # The shop an incident belongs to: the commonest host in its evidence.
    names = shop_of_host()
    counts: dict[str, int] = {}

    for event in evidence or []:
        context = event.get("context") if isinstance(event, dict) else None
        host = context.get("host") if isinstance(context, dict) else None

        if host in names:
            counts[names[host]] = counts.get(names[host], 0) + 1

    return max(counts, key=counts.get) if counts else "unknown"
