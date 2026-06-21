"""Detect prompt injection patterns in agent config files."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "prompt_injection_override",
        Severity.CRITICAL,
        "Instruction override: attempts to reset agent context",
    ),
    (
        re.compile(r"you\s+are\s+now\s+(a|an)\s+", re.IGNORECASE),
        "persona_hijack",
        Severity.HIGH,
        "Persona hijack: redefines agent identity",
    ),
    (
        re.compile(r"(system|assistant)\s*:\s*", re.IGNORECASE),
        "fake_role_claim",
        Severity.HIGH,
        "Fake role marker: mimics system/assistant message boundary",
    ),
    (
        re.compile(r"do\s+not\s+follow\s+(any|your)\s+(safety|security|previous)", re.IGNORECASE),
        "safety_override",
        Severity.CRITICAL,
        "Safety override: instructs agent to ignore safety guidelines",
    ),
    (
        re.compile(r"(jailbreak|DAN|do\s+anything\s+now)", re.IGNORECASE),
        "jailbreak_language",
        Severity.CRITICAL,
        "Jailbreak pattern: known alignment bypass technique",
    ),
    (
        re.compile(r"pretend\s+(you\s+)?(are|have|can)\s+", re.IGNORECASE),
        "hypothetical_framing",
        Severity.MEDIUM,
        "Hypothetical framing: may trick agent into unsafe behavior",
    ),
    (
        re.compile(r"<\|(im_start|im_end|endoftext)\|>", re.IGNORECASE),
        "token_boundary_injection",
        Severity.CRITICAL,
        "Token boundary injection: attempts to manipulate tokenizer control sequences",
    ),
    (
        re.compile(r"\\u200[b-f]|\\u00ad|\\ufeff", re.IGNORECASE),
        "invisible_unicode",
        Severity.HIGH,
        "Invisible unicode characters: may hide instructions from human review",
    ),
]


def check_injection(path: Path, content: str) -> list[Finding]:
    """Scan content for prompt injection patterns."""
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
                    taxonomy_id="MCP-T01",
                    atlas_id="J1",
                ))
    return findings
