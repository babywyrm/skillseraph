"""Detect persistent behavior change instructions."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"(from\s+now\s+on|in\s+(all\s+)?future\s+(runs?|sessions?|conversations?))", re.IGNORECASE),
        "persistent_behavior",
        Severity.HIGH,
        "Persistent behavior change: instructs modification across sessions",
    ),
    (
        re.compile(r"(always|permanently|forever)\s+(remember|apply|use|follow)\s+", re.IGNORECASE),
        "permanent_instruction",
        Severity.MEDIUM,
        "Permanent instruction: attempts to anchor behavior indefinitely",
    ),
    (
        re.compile(r"(write|add|append|create)\s+(this\s+)?(to|in)\s+(your\s+)?(memory|rules?|config)", re.IGNORECASE),
        "self_modify_config",
        Severity.CRITICAL,
        "Self-modification: instructs agent to write to its own config",
    ),
    (
        re.compile(r"(install|register|add)\s+(a\s+)?(hook|callback|webhook|cron|timer)", re.IGNORECASE),
        "persistence_mechanism",
        Severity.HIGH,
        "Persistence mechanism: registers ongoing execution",
    ),
]


def check_persistence(path: Path, content: str) -> list[Finding]:
    """Scan for persistent behavior change patterns."""
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
                    taxonomy_id="MCP-T14",
                    atlas_id="J4",
                ))
    return findings
