"""Detect fabricated authority / fake authorization context in agent configs.

Threat class: an attacker plants language in a skill/rule/instruction file that
pre-authorizes the agent for privileged actions by fabricating an approval,
maintenance window, or security sign-off. This is the static-config analog of
indirect prompt injection (MCP-T02 / OWASP LLM01), where untrusted content is
crafted to assert authority it does not have in order to defeat a downstream
guardrail or human reviewer.

References: OWASP Top 10 for LLM Applications (LLM01 Prompt Injection),
OWASP MCP Top 10 (MCP06 Prompt Injection).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"(maintenance\s+(window|mode)\s+(is\s+)?(open|active|enabled|authorized))", re.IGNORECASE),
        "fake_maintenance_window",
        Severity.HIGH,
        "Fabricated maintenance window: pre-authorizes privileged operations",
    ),
    (
        re.compile(r"(approved|authorized|cleared|signed.?off)\s+by\s+(the\s+)?(security|ops|admin|sysadmin|management|team)", re.IGNORECASE),
        "fake_approval_claim",
        Severity.HIGH,
        "Fabricated approval: claims authorization from a trusted party",
    ),
    (
        re.compile(r"(you\s+are|you'?re)\s+(pre.?)?(authorized|approved|cleared|permitted)\s+to", re.IGNORECASE),
        "preauthorization_claim",
        Severity.HIGH,
        "Pre-authorization claim: asserts the agent already has permission",
    ),
    (
        re.compile(r"(emergency|incident|urgent)\s+(override|authorization|access|approval)", re.IGNORECASE),
        "emergency_override_claim",
        Severity.HIGH,
        "Emergency override claim: invokes urgency to bypass controls",
    ),
    (
        re.compile(r"(this\s+(has\s+been|is)\s+(already\s+)?(reviewed|approved|vetted|verified|trusted))", re.IGNORECASE),
        "false_trust_assertion",
        Severity.MEDIUM,
        "False trust assertion: claims content is already vetted",
    ),
    (
        re.compile(r"(ticket|change\s?request|CR|JIRA|INC)[-#\s]?\d{2,}.*?(approved|authorized|emergency)", re.IGNORECASE),
        "fake_ticket_reference",
        Severity.MEDIUM,
        "Fake ticket reference: fabricates a change-management trail",
    ),
    (
        re.compile(r"(all\s+operators?\s+(are\s+)?cleared|operators?\s+(have\s+been\s+)?notified)", re.IGNORECASE),
        "operator_clearance_claim",
        Severity.MEDIUM,
        "Operator clearance claim: fabricates team-wide authorization",
    ),
]


def check_authority_fabrication(path: Path, content: str) -> list[Finding]:
    """Scan for fabricated authorization / approval context."""
    findings: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        for pattern, check_name, severity, title in _PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    path=path,
                    check=check_name,
                    severity=severity,
                    title=title,
                    detail=f"Line {line_num}: {line.strip()[:120]}",
                    line=line_num,
                    evidence=line.strip()[:200],
                    taxonomy_id="MCP-T02",
                    atlas_id="J1",
                ))
    return findings
