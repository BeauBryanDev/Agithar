
# OWASP Top 10:2025 — verified reference lookup for Aegis-CyberSec-Guard.

# Source: https://owasp.org/Top10/2025/ (official, CC BY 3.0 Unported License).
# Fetched and verified directly from OWASP.org on the date this file was built .
# Usage as a tool for the orchestrator Agent:
#    from owasp_top10_2025 import OWASP_TOP_10, lookup, search_by_cwe

  #  lookup("A05")                 -> full entry for Injection
  #  lookup("a05")                 -> same, case-insensitive
  #  search_by_cwe("CWE-89")       -> ["A05"]  (SQL Injection maps to A05)

# O(1) by design: a dict keyed by category ID. No embeddings, no vector search, no
# possibility of hallucination — either the ID is a key in this dict, or it is not.

OWASP_TOP_10_2025 = {
    "A01": {
        "id": "A01:2025",
        "title": "Broken Access Control",
        "rank_change": "unchanged at #1 since 2021",
        "summary": (
            "Users can act outside their intended permissions: bypassing access checks "
            "via URL/parameter tampering, viewing or editing another user's records via "
            "insecure direct object references, missing access control on API write "
            "endpoints, privilege escalation, or CORS misconfiguration allowing untrusted "
            "origins to call the API."
        ),
        "key_prevention": [
            "Deny by default except for public resources.",
            "Enforce access control server-side, once, reused throughout the app.",
            "Model access control around record ownership, not free create/read/update/delete.",
            "Rate-limit API/controller access; log and alert on access-control failures.",
        ],
        "key_cwes": ["CWE-284 Improper Access Control", "CWE-285 Improper Authorization",
                     "CWE-352 CSRF", "CWE-918 SSRF", "CWE-862 Missing Authorization"],
        "url": "https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/",
    },
    "A02": {
        "id": "A02:2025",
        "title": "Security Misconfiguration",
        "rank_change": "up from #5 in 2021",
        "summary": (
            "A system, application, or cloud service set up incorrectly from a security "
            "standpoint: unnecessary features/ports/accounts enabled, default credentials "
            "left unchanged, overly verbose error messages, missing security headers, or "
            "insecure cloud storage permissions."
        ),
        "key_prevention": [
            "Repeatable, automated hardening process across dev/QA/prod environments.",
            "Minimal platform: remove unused features, samples, and documentation.",
            "Review cloud storage permissions (e.g. S3 bucket ACLs) as part of patch management.",
            "Segment application architecture; send security headers/directives to clients.",
        ],
        "key_cwes": ["CWE-16 Configuration", "CWE-611 XXE", "CWE-489 Active Debug Code"],
        "url": "https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/",
    },
    "A03": {
        "id": "A03:2025",
        "title": "Software Supply Chain Failures",
        "rank_change": "expanded scope from 2021's 'Vulnerable and Outdated Components'; #1 ranked concern in the community survey",
        "summary": (
            "Breakdowns or malicious changes in the process of building, distributing, or "
            "updating software — vulnerable/unmaintained dependencies (direct or "
            "transitive), untracked component versions, weak CI/CD security, or components "
            "pulled from untrusted sources. Includes SolarWinds-style vendor compromise and "
            "npm/package-registry worm attacks (e.g. the 2025 Shai-Hulud npm worm)."
        ),
        "key_prevention": [
            "Maintain a Software Bill of Materials (SBOM); track transitive dependencies.",
            "Continuously monitor CVE/NVD/OSV for components in use; automate with SCA tools.",
            "Only pull components from trusted, signed sources over secure links.",
            "Harden CI/CD: separation of duties, signed builds, tamper-evident logs.",
        ],
        "key_cwes": ["CWE-1104 Use of Unmaintained Third Party Components",
                     "CWE-1395 Dependency on Vulnerable Third-Party Component"],
        "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
    },
    "A04": {
        "id": "A04:2025",
        "title": "Cryptographic Failures",
        "rank_change": "down two, from #2 in 2021",
        "summary": (
            "Missing, weak, or misapplied cryptography — cleartext transmission or storage "
            "of sensitive data, weak/predictable random number generation, deprecated hash "
            "functions (MD5/SHA1), missing certificate validation, or reused/predictable "
            "initialization vectors."
        ),
        "key_prevention": [
            "Classify data sensitivity; encrypt sensitive data at rest and in transit (TLS >= 1.2).",
            "Use vetted crypto libraries; never roll your own; use authenticated encryption.",
            "Store passwords with a strong adaptive salted hash (Argon2, scrypt, PBKDF2).",
            "Avoid deprecated algorithms (MD5, SHA1, CBC without authentication).",
        ],
        "key_cwes": ["CWE-327 Broken/Risky Cryptographic Algorithm", "CWE-330 Insufficiently Random Values",
                     "CWE-798 Use of Hard-coded Credentials (crypto keys)"],
        "url": "https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/",
    },
    "A05": {
        "id": "A05:2025",
        "title": "Injection",
        "rank_change": "down two, from #3 in 2021",
        "summary": (
            "Untrusted input sent to an interpreter (SQL, OS shell, LDAP, ORM query "
            "language) executes as commands instead of being treated as data. Covers SQL "
            "injection, OS command injection, XSS, and template injection. Prompt injection "
            "against LLMs is now cross-referenced here via the OWASP GenAI/LLM Top 10."
        ),
        "key_prevention": [
            "Use parameterized queries / safe APIs that separate data from commands.",
            "Positive server-side input validation as a secondary defense.",
            "Escape special characters with the interpreter's specific escape syntax when parameterization is not possible.",
            "SAST/DAST/IAST in CI/CD to catch injection flaws pre-deployment.",
        ],
        "key_cwes": ["CWE-89 SQL Injection", "CWE-79 Cross-site Scripting", "CWE-78 OS Command Injection"],
        "url": "https://owasp.org/Top10/2025/A05_2025-Injection/",
    },
    "A06": {
        "id": "A06:2025",
        "title": "Insecure Design",
        "rank_change": "down two, from #4 in 2021",
        "summary": (
            "Missing or ineffective security controls at the design/architecture level — "
            "distinct from implementation bugs. A perfect implementation cannot fix a "
            "design that never accounted for the threat. Includes missing threat modeling, "
            "unsafe business-logic flows (e.g. no limit on bulk bookings enabling fraud), "
            "and weak credential-recovery flows like security questions."
        ),
        "key_prevention": [
            "Integrate threat modeling into design/refinement, not as an afterthought.",
            "Maintain a library of secure design patterns / paved-road components.",
            "Write misuse-case tests, not just use-case tests, for critical flows.",
            "Segregate tenants and tiers by design, not by later patching.",
        ],
        "key_cwes": ["CWE-501 Trust Boundary Violation", "CWE-799 Improper Control of Interaction Frequency"],
        "url": "https://owasp.org/Top10/2025/A06_2025-Insecure_Design/",
    },
    "A07": {
        "id": "A07:2025",
        "title": "Authentication Failures",
        "rank_change": "unchanged at #7 since 2021 (renamed from 'Identification and Authentication Failures')",
        "summary": (
            "A system fails to correctly verify identity, allowing credential stuffing, "
            "brute force, weak/default passwords, insecure credential recovery, missing "
            "MFA, or improper session invalidation on logout."
        ),
        "key_prevention": [
            "Enforce multi-factor authentication where possible.",
            "Check new/changed passwords against known-breached credential lists.",
            "Use uniform error messages for login/recovery to prevent account enumeration.",
            "Server-side session manager: new high-entropy session ID after login, proper invalidation.",
        ],
        "key_cwes": ["CWE-287 Improper Authentication", "CWE-307 Improper Restriction of Excessive Authentication Attempts",
                     "CWE-798 Use of Hard-coded Credentials"],
        "url": "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
    },
    "A08": {
        "id": "A08:2025",
        "title": "Software or Data Integrity Failures",
        "rank_change": "unchanged at #8 (renamed from 'Software and Data Integrity Failures')",
        "summary": (
            "Code or data is trusted without verifying its integrity — unsigned auto-update "
            "mechanisms, packages pulled from untrusted sources, or insecure deserialization "
            "of attacker-controllable serialized objects leading to remote code execution."
        ),
        "key_prevention": [
            "Verify software/data origin and integrity with digital signatures.",
            "Only consume trusted, vetted package repositories.",
            "Segregate and access-control the CI/CD pipeline itself.",
            "Never deserialize unsigned/unencrypted data from untrusted clients without an integrity check.",
        ],
        "key_cwes": ["CWE-502 Deserialization of Untrusted Data", "CWE-829 Inclusion of Functionality from Untrusted Control Sphere"],
        "url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
    },
    "A09": {
        "id": "A09:2025",
        "title": "Security Logging and Alerting Failures",
        "rank_change": "unchanged at #9 (renamed to emphasize alerting, not just logging)",
        "summary": (
            "Attacks and breaches cannot be detected or responded to without adequate "
            "logging and alerting. Includes inconsistent login logging, tamperable logs, "
            "logs never monitored, PII/PHI logged insecurely, and alert fatigue from too "
            "many false positives burying real incidents."
        ),
        "key_prevention": [
            "Log all security-relevant events (success AND failure) with sufficient context.",
            "Protect log integrity (append-only, tamper-evident).",
            "Establish SOC monitoring/alerting playbooks tied to real use cases.",
            "Consider honeytokens as near-zero-false-positive attacker traps.",
        ],
        "key_cwes": ["CWE-778 Insufficient Logging", "CWE-532 Insertion of Sensitive Information into Log File"],
        "url": "https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/",
    },
    "A10": {
        "id": "A10:2025",
        "title": "Mishandling of Exceptional Conditions",
        "rank_change": "NEW category in 2025",
        "summary": (
            "Failure to prevent, detect, or properly respond to unusual/unpredictable "
            "runtime conditions — unhandled exceptions, failing open instead of closed, "
            "verbose error messages leaking sensitive info, or partial transaction "
            "rollback leaving state corrupted. New in the 2025 edition, split out from "
            "the more general 'poor code quality' framing."
        ),
        "key_prevention": [
            "Catch and handle every exception at the point it occurs; never rely only on high-level catch-alls.",
            "Fail closed: fully roll back partial transactions on error.",
            "Centralized error handling, logging, and alerting — one pattern org-wide.",
            "Add rate limits / resource quotas to prevent exhaustion-driven exceptional states.",
        ],
        "key_cwes": ["CWE-755 Improper Handling of Exceptional Conditions", "CWE-636 Not Failing Securely ('Failing Open')",
                     "CWE-209 Generation of Error Message Containing Sensitive Information"],
        "url": "https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/",
    },
}


def lookup(category_id: str) -> dict | None:
    """O(1) lookup by category ID. Case-insensitive, tolerant of 'A01' or 'A01:2025'."""
    key = category_id.strip().upper().split(":")[0]
    return OWASP_TOP_10_2025.get(key)


def search_by_cwe(cwe_ref: str) -> list[str]:
    """
    Linear scan over 10 entries (still effectively instant) to find which category
    lists a given CWE among its key_cwes. Not exhaustive — key_cwes is a curated
    subset, not the full CWE mapping (which runs into hundreds per category on the
    official pages). For an exhaustive CWE->category map, fetch the 'List of Mapped
    CWEs' section from the official url of each entry instead of relying on this.
    """
    cwe_ref = cwe_ref.strip().upper()
    if cwe_ref.isdigit():
        cwe_ref = f"CWE-{cwe_ref}"
    matches = []
    for key, entry in OWASP_TOP_10_2025.items():
        # Exact match on the ID token ("CWE-79"), so "CWE-79" does not hit "CWE-798".
        if any(c.split()[0].upper() == cwe_ref for c in entry["key_cwes"]):
            matches.append(key)
    return matches


# For Testings

if __name__ == "__main__":
    # Quick self-check
    a05 = lookup("a05")
    assert a05 is not None and a05["title"] == "Injection"
    assert lookup("A99") is None
    assert "A05" in search_by_cwe("CWE-89")
    assert search_by_cwe("cwe-79") == ["A05"]
    assert search_by_cwe("79") == ["A05"]
    print(f"Loaded {len(OWASP_TOP_10_2025)} categories. Self-check passed.")
