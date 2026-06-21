"""Detect encoded/obfuscated payloads in agent configs."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_BLOB_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{64,}")
_DATA_URI_RE = re.compile(r"data:[^;]+;base64,")
_UNICODE_ESCAPE_RE = re.compile(r"(\\u[0-9a-fA-F]{4}){4,}")


def check_encoding(path: Path, content: str) -> list[Finding]:
    """Scan for encoded/obfuscated payloads that may hide instructions."""
    findings: list[Finding] = []
    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        if _BASE64_RE.search(line) and len(line.strip()) > 80:
            findings.append(Finding(
                path=path,
                check="base64_blob",
                severity=Severity.MEDIUM,
                title="Large base64-encoded blob",
                detail=f"Line {line_num}: potential encoded payload ({len(line.strip())} chars)",
                line=line_num,
                evidence=line.strip()[:100] + "...",
                taxonomy_id="MCP-T01",
                atlas_id="J8",
            ))

        if _HEX_BLOB_RE.search(line):
            findings.append(Finding(
                path=path,
                check="hex_blob",
                severity=Severity.MEDIUM,
                title="Large hex-encoded blob",
                detail=f"Line {line_num}: potential obfuscated payload",
                line=line_num,
                evidence=line.strip()[:100] + "...",
                taxonomy_id="MCP-T01",
                atlas_id="J8",
            ))

        if _DATA_URI_RE.search(line):
            findings.append(Finding(
                path=path,
                check="data_uri_payload",
                severity=Severity.HIGH,
                title="Data URI with base64 payload",
                detail=f"Line {line_num}: embedded data URI may contain hidden instructions",
                line=line_num,
                evidence=line.strip()[:100] + "...",
                taxonomy_id="MCP-T01",
                atlas_id="J8",
            ))

        if _UNICODE_ESCAPE_RE.search(line):
            findings.append(Finding(
                path=path,
                check="unicode_escape_sequence",
                severity=Severity.MEDIUM,
                title="Unicode escape sequence chain",
                detail=f"Line {line_num}: encoded unicode may hide instructions",
                line=line_num,
                evidence=line.strip()[:100] + "...",
                taxonomy_id="MCP-T01",
                atlas_id="J8",
            ))

    return findings
