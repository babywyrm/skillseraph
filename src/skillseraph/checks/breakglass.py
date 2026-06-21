"""Detect embedded break-glass / emergency-override tokens in agent configs.

Threat class: "break-glass" tokens are emergency overrides that bypass normal
authorization. When such a token (or instructions to use one) is planted in an
agent config or instruction file, it lets an attacker pre-arm the agent to
escalate privileges or bypass admission/approval controls on demand.

References: OWASP MCP Top 10 (MCP02 Privilege Escalation, MCP07 Insufficient
Authentication).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"\bbreak.?glass\b", re.IGNORECASE),
        "breakglass_reference",
        Severity.HIGH,
        "Break-glass reference: emergency override mechanism in config",
    ),
    (
        re.compile(r"(override|bypass|emergency|master)[-_\s]?(token|key|code|password|secret)\s*[:=]", re.IGNORECASE),
        "override_token_assignment",
        Severity.CRITICAL,
        "Override token assignment: embeds an emergency-access credential",
    ),
    (
        re.compile(r"(use|include|append|add)\s+(this\s+)?(token|annotation|header|flag)\s+to\s+(bypass|override|escalate|approve)", re.IGNORECASE),
        "override_usage_instruction",
        Severity.CRITICAL,
        "Instruction to use a token to bypass/override controls",
    ),
    (
        re.compile(r"(admission|policy|guardrail|gate)\s+(bypass|override|exception)\s+(token|code|flag|annotation)", re.IGNORECASE),
        "policy_bypass_token",
        Severity.CRITICAL,
        "Policy/admission bypass token referenced in config",
    ),
    (
        re.compile(r"(skip|disable|ignore)\s+(the\s+)?(admission|policy|approval|guardrail)\s+(check|gate|controller|webhook)", re.IGNORECASE),
        "admission_skip_instruction",
        Severity.HIGH,
        "Instruction to skip an admission/policy control",
    ),
]


def check_breakglass(path: Path, content: str) -> list[Finding]:
    """Scan for break-glass / emergency-override tokens and instructions."""
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
                    taxonomy_id="MCP-T09",
                    atlas_id="J1",
                ))
    return findings
