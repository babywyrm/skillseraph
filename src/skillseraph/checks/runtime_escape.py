"""Container/orchestrator runtime escape-surface checks (rules in rules/runtime_escape.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_runtime_escape(path: Path, content: str) -> list[Finding]:
    return run_category("runtime_escape", path, content)
