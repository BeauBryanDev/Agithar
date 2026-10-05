import re
from typing import Any

from app.agent.review import MAX_DRAFT_CHARS
from app.security.sanitize import sanitize_string

HEADING = re.compile(r"^(#{1,5})(?=\s)", re.MULTILINE)
SHORT_CHARS = 200
NO_DRAFT = "_No draft was produced._"
NO_VERDICT = {
    "verdict": "needs_human",
    "needs_human": True,
    "confidence": 0.0,
    "mitre_technique": None,
    "owasp_category": None,
    "summary": "No verdict was produced by the investigation.",
}


def short(value: Any, limit: int = SHORT_CHARS) -> str:
    return sanitize_string(str(value), limit)


def demote_headings(text: str) -> str:
    # The drafts are nested under the report's own sections.
    return HEADING.sub(r"\1#", text)


def force_review(verdict: dict[str, Any] | None) -> dict[str, Any]:
    # An unapproved draft or a missing verdict always goes to a human.
    base = dict(verdict) if verdict else dict(NO_VERDICT)
    base["verdict"] = "needs_human"
    base["needs_human"] = True

    return base


def draft_section(title: str, 
                  draft: str | None, 
                  status: str) -> str:
    body = (
        demote_headings(
            sanitize_string(draft, 
                            MAX_DRAFT_CHARS, 
                            keep_newlines=True)
            
        ) if draft else NO_DRAFT
    )
    label = "approved"

    if status != "approved":
        label = "UNAPPROVED, the review limit was reached"

    return f"## {title} ({label})\n\n{body}"


def verdict_lines(verdict: dict[str, Any]) -> str:
    
    confidence = float(verdict.get("confidence", 0.0))
    human = "yes" if verdict.get("needs_human") else "no"

    return "\n".join(
        [
            f"- Verdict: {short(verdict.get('verdict'), 32)}",
            f"- Confidence: {confidence:.2f}",
            f"- Human review required: {human}",
            f"- MITRE: {short(verdict.get('mitre_technique') or 'none', 32)}",
            f"- OWASP: {short(verdict.get('owasp_category') or 'none', 32)}",
            f"- Summary: {short(verdict.get('summary') or '', 1000)}",
        ]
    )


def case_lines(case: dict[str, Any], 
               incident_id: int | None
               ) -> str:
    
    names = case["contributing_sensors"]
    sensors = ", ".join(short(name, 64) for name in names)
    saved = incident_id if incident_id is not None else "not saved"

    return "\n".join(
        [
            f"- Incident: {saved}",
            f"- Case: {short(case['case_id'], 80)}",
            f"- Severity: {short(case['severity'], 16)}",
            f"- IP: {short(case['ip'], 64)}",
            f"- Composite score: {float(case['composite_score']):.2f}",
            f"- Sensors: {sensors}",
        ]
    )


def build_report(
    case: dict[str, Any],
    incident_id: int | None,
    verdict: dict[str, Any],
    blue: tuple[str | None, str],
    red: tuple[str | None, str],
) -> str:
    # Only structured case fields, the verdict and the two reviewed drafts.
    parts = [
        "# Incident report",
        "## Case\n\n" + case_lines(case, incident_id),
        "## Verdict\n\n" + verdict_lines(verdict),
        draft_section("Defensive report", *blue),
        draft_section("Exposure report", *red),
    ]

    return "\n\n".join(parts) + "\n"
