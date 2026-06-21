"""Runtime blocklist-bypass checks (rules in rules/runtime_bypass.yaml).

Threat class: invoking an allowed language runtime to perform an action a
blocked binary would (file I/O, process spawn, network). References: GTFOBins,
OWASP MCP Top 10 (MCP05 Command Injection).
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_runtime_bypass(path: Path, content: str) -> list[Finding]:
    return run_category("runtime_bypass", path, content)
