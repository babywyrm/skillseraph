"""Detect review suppression and stealth instructions."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"(don.t|do\s+not|never)\s+(mention|include|show|reveal|disclose)\s+.*(commit|PR|review|summary|changelog)", re.IGNORECASE),
        "review_suppression",
        Severity.HIGH,
        "Instructs hiding changes from review/PR/commit messages",
    ),
    (
        re.compile(r"(hide|conceal|obscure|omit)\s+(this|these|the)\s+(change|modif|addition|file)", re.IGNORECASE),
        "change_concealment",
        Severity.HIGH,
        "Instructs concealing modifications",
    ),
    (
        re.compile(r"(act|operate|work)\s+(silently|quietly|invisibly|in.?the.?background)", re.IGNORECASE),
        "stealth_operation",
        Severity.MEDIUM,
        "Instructs silent/invisible operation",
    ),
    (
        re.compile(r"(don.t|do\s+not)\s+(tell|inform|alert|notify|warn)\s+(the\s+)?(user|human|developer|operator)", re.IGNORECASE),
        "user_deception",
        Severity.HIGH,
        "Instructs hiding actions from the user",
    ),
]


def check_suppression(path: Path, content: str) -> list[Finding]:
    """Scan for review suppression and stealth patterns."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
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
                    taxonomy_id="MCP-T13",
                    atlas_id="J7",
                ))
    return findings
