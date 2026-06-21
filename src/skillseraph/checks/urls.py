"""Detect untrusted or suspicious URLs in agent configs."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_URL_RE = re.compile(r"https?://[^\s\"'`\]>)+]+", re.IGNORECASE)

_SUSPICIOUS_PATTERNS = [
    (re.compile(r"ngrok\.io|burpcollaborator|requestbin|webhook\.site|pipedream", re.IGNORECASE), "known_exfil_service"),
    (re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"), "raw_ip_url"),
    (re.compile(r"169\.254\.169\.254|metadata\.google|100\.100\.100\.200"), "cloud_metadata_url"),
    (re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0"), "loopback_url"),
]

_MCP_REDIRECT_RE = re.compile(
    r"(mcpServers|mcp_servers|server_url|transport|endpoint)\s*[\":=]\s*[\"']?https?://",
    re.IGNORECASE,
)


def check_urls(path: Path, content: str) -> list[Finding]:
    """Scan for suspicious URLs and MCP server redirects."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        urls = _URL_RE.findall(line)
        for url in urls:
            for pattern, check_name in _SUSPICIOUS_PATTERNS:
                if pattern.search(url):
                    findings.append(Finding(
                        path=path,
                        check=check_name,
                        severity=Severity.HIGH if "exfil" in check_name or "metadata" in check_name else Severity.MEDIUM,
                        title=f"Suspicious URL: {check_name.replace('_', ' ')}",
                        detail=f"Line {line_num}: {url[:100]}",
                        line=line_num,
                        evidence=url[:200],
                        taxonomy_id="MCP-T06",
                        atlas_id="J1",
                    ))

        if _MCP_REDIRECT_RE.search(line):
            findings.append(Finding(
                path=path,
                check="mcp_server_redirect",
                severity=Severity.CRITICAL,
                title="MCP server endpoint redirect in config",
                detail=f"Line {line_num}: config points MCP traffic to external URL",
                line=line_num,
                evidence=line.strip()[:200],
                taxonomy_id="MCP-T14",
                atlas_id="J1",
            ))

    return findings
