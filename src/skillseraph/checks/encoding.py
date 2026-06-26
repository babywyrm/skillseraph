"""Atlas J8 — Encoded/obfuscated payload checks (rules in rules/encoding.yaml).

Detects base64 blobs, hex strings, unicode-escape chains, data URIs, and
decode-then-execute patterns *stored* in agent config files to evade keyword
scanners. Execution-time obfuscation (e.g. `base64 -d | sh`) lives in
runtime_bypass. References: OWASP MCP Top 10 (MCP05, MCP06).
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_encoding(path: Path, content: str) -> list[Finding]:
    return run_category("encoding", path, content)
