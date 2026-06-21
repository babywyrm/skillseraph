"""Break-glass / override-token checks (rules in rules/breakglass.yaml).

Threat class: emergency-override tokens or instructions planted in a config to
pre-arm an agent to escalate privileges or bypass admission/approval controls.
References: OWASP MCP Top 10 (MCP02 Privilege Escalation, MCP07 Insufficient Auth).
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_breakglass(path: Path, content: str) -> list[Finding]:
    return run_category("breakglass", path, content)
