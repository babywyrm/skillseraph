"""Detect dangerous tool invocation patterns in agent configs."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_DANGEROUS_TOOLS_RE = re.compile(
    r"(shell|bash|exec|system|subprocess|os\.popen|eval|rm\s+-rf|curl\s+\|.*sh|wget\s+.*\|)",
    re.IGNORECASE,
)

_PATH_TRAVERSAL_RE = re.compile(r"\.\./\.\./|/etc/(passwd|shadow|hosts)|/root/|~/.ssh/")

_SENSITIVE_PATHS_RE = re.compile(
    r"(/\.env|/\.aws/|/\.kube/config|/\.ssh/id_|/\.git/config|/\.npmrc|/\.pypirc)",
    re.IGNORECASE,
)

_REMOTE_BOOTSTRAP_RE = re.compile(
    r"(curl|wget|fetch)\s+.*(https?://|\|)\s*(sh|bash|python|node)",
    re.IGNORECASE,
)


def check_tool_abuse(path: Path, content: str) -> list[Finding]:
    """Scan for dangerous tool invocations and path access."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        if _DANGEROUS_TOOLS_RE.search(line):
            findings.append(Finding(
                path=path,
                check="dangerous_tool_invocation",
                severity=Severity.HIGH,
                title="Dangerous tool/command invocation",
                detail=f"Line {line_num}: {line.strip()[:120]}",
                line=line_num,
                evidence=line.strip()[:200],
                taxonomy_id="MCP-T09",
                atlas_id="J4",
            ))

        if _PATH_TRAVERSAL_RE.search(line):
            findings.append(Finding(
                path=path,
                check="path_traversal",
                severity=Severity.HIGH,
                title="Path traversal pattern",
                detail=f"Line {line_num}: accesses sensitive system paths",
                line=line_num,
                evidence=line.strip()[:200],
                taxonomy_id="MCP-T06",
                atlas_id="J1",
            ))

        if _SENSITIVE_PATHS_RE.search(line):
            findings.append(Finding(
                path=path,
                check="sensitive_path_access",
                severity=Severity.MEDIUM,
                title="References sensitive credential path",
                detail=f"Line {line_num}: {line.strip()[:120]}",
                line=line_num,
                evidence=line.strip()[:200],
                taxonomy_id="MCP-T07",
                atlas_id="J1",
            ))

        if _REMOTE_BOOTSTRAP_RE.search(line):
            findings.append(Finding(
                path=path,
                check="remote_bootstrap",
                severity=Severity.CRITICAL,
                title="Remote code bootstrap (curl|sh pattern)",
                detail=f"Line {line_num}: downloads and executes remote code",
                line=line_num,
                evidence=line.strip()[:200],
                taxonomy_id="MCP-T08",
                atlas_id="J4",
            ))

    return findings
