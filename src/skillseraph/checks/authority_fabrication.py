"""Fabricated authority checks (rules in rules/authority_fabrication.yaml).

Threat class: untrusted content that asserts authority it does not have
(fake approvals, maintenance windows, pre-authorization) to defeat a downstream
guardrail or human reviewer. Static-config analog of indirect prompt injection
(OWASP LLM01 / OWASP MCP06).
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_authority_fabrication(path: Path, content: str) -> list[Finding]:
    return run_category("authority_fabrication", path, content)
