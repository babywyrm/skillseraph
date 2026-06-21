"""Detect permission/sandbox bypass instructions."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"(auto.?approve|skip.?confirm|bypass.?sandbox|disable.?safety)", re.IGNORECASE),
        "sandbox_bypass",
        Severity.CRITICAL,
        "Sandbox/approval bypass instruction",
    ),
    (
        re.compile(r"(without\s+(user\s+)?consent|without\s+asking|silently|secretly)", re.IGNORECASE),
        "consent_bypass",
        Severity.HIGH,
        "Operates without user consent",
    ),
    (
        re.compile(r"(execute|run|invoke)\s+(any|all|arbitrary)\s+(command|tool|script)", re.IGNORECASE),
        "arbitrary_execution",
        Severity.CRITICAL,
        "Arbitrary command/tool execution instruction",
    ),
    (
        re.compile(r"(disable|ignore|skip)\s+(the\s+)?(linter|review|check|validation|policy)", re.IGNORECASE),
        "validation_skip",
        Severity.MEDIUM,
        "Instructs skipping validation/review",
    ),
    (
        re.compile(r"(root|admin|sudo|privileged)\s+(access|mode|shell|execution)", re.IGNORECASE),
        "privilege_request",
        Severity.HIGH,
        "Requests elevated privileges",
    ),
]


def check_permission_bypass(path: Path, content: str) -> list[Finding]:
    """Scan for permission/sandbox bypass patterns."""
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
                    taxonomy_id="MCP-T09",
                    atlas_id="J1",
                ))
    return findings
