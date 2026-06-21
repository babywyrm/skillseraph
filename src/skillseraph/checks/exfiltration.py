"""Detect exfiltration instructions in agent config files."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"(harvest|collect|gather|exfil)\s+(all\s+)?(tokens?|cred|secret|key|password|api.?key)", re.IGNORECASE),
        "exfil_credentials",
        Severity.CRITICAL,
        "Credential harvesting instruction",
    ),
    (
        re.compile(r"send\s+(to|data|results?|output)\s+(https?://|wss?://)", re.IGNORECASE),
        "exfil_to_url",
        Severity.CRITICAL,
        "Data exfiltration to external URL",
    ),
    (
        re.compile(r"read\s+(the\s+)?(\.env|ssh.key|id_rsa|id_ed25519|\.aws/cred|\.kube/config)", re.IGNORECASE),
        "secret_file_access",
        Severity.HIGH,
        "Instruction to read sensitive files",
    ),
    (
        re.compile(r"(curl|wget|fetch|http)\s+.*\s+(POST|PUT)\s+", re.IGNORECASE),
        "outbound_data_push",
        Severity.MEDIUM,
        "Outbound data push instruction",
    ),
    (
        re.compile(r"(environment|process\.env|os\.environ)\s*.*(token|secret|key|pass)", re.IGNORECASE),
        "env_secret_access",
        Severity.HIGH,
        "Environment variable secret access",
    ),
]


def check_exfiltration(path: Path, content: str) -> list[Finding]:
    """Scan content for exfiltration patterns."""
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
                    taxonomy_id="MCP-T12",
                    atlas_id="J1",
                ))
    return findings
