import re

from app.rag.mitre_attack import MitreError, check_technique

MAX_REVISIONS = 2
MIN_DRAFT_CHARS = 200
MAX_DRAFT_CHARS = 6000
MITRE_ID = re.compile(r"\bT[0-9]{4}(?:\.[0-9]{3})?\b")
MAX_MITRE_CHECKS = 20

# The report template is still the user's to give: change the headings here.
REQUIRED_SECTIONS = {
    "blue": ("Summary", "Evidence", "Recommended actions"),
    "red": ("Summary", "Exposure", "Impact", "Mitigation"),
}

# The red report describes exposure, never how to exploit it.
RED_FORBIDDEN = (
    "<script",
    "union select",
    "or 1=1",
    "rm -rf",
    "bash -i",
    "nc -e",
    "/bin/sh -c",
    "powershell -enc",
)


def has_heading(draft: str, title: str) -> bool:
    pattern = rf"^#{{1,4}}\s*{re.escape(title)}\b"

    return re.search(pattern, draft, re.IGNORECASE | re.MULTILINE) is not None


def bad_mitre_ids(draft: str) -> list[str]:
    ids = list(dict.fromkeys(MITRE_ID.findall(draft)))[:MAX_MITRE_CHECKS]
    problems = []

    for technique_id in ids:
        try:
            status = check_technique(technique_id)["status"]

        except MitreError:
            # Without the index nothing can be checked: do not block the report.
            return []

        if status != "active":
            problems.append(f"MITRE technique {technique_id} is {status}")

    return problems


def check_draft(draft: str | None, color: str) -> list[str]:
    # Fixed messages only: the draft text is never echoed back to the writer.
    if not draft or not draft.strip():
        return ["the draft is empty"]

    problems = []

    if len(draft) < MIN_DRAFT_CHARS:
        problems.append(f"the draft is shorter than {MIN_DRAFT_CHARS} chars")

    if len(draft) > MAX_DRAFT_CHARS:
        problems.append(f"the draft is longer than {MAX_DRAFT_CHARS} chars")

    if "```" in draft:
        problems.append("remove code blocks")

    for title in REQUIRED_SECTIONS[color]:
        if not has_heading(draft, title):
            problems.append(f"missing section: {title}")

    problems.extend(bad_mitre_ids(draft))

    if color == "red":
        lowered = draft.lower()

        if any(term in lowered for term in RED_FORBIDDEN):
            problems.append("remove exploitation or payload content")

    return problems
