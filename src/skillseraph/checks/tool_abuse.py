"""Dangerous tool invocation checks (rules in rules/tool_abuse.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_tool_abuse(path: Path, content: str) -> list[Finding]:
    return run_category("tool_abuse", path, content)
