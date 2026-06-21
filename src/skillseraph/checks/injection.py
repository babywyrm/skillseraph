"""Prompt injection checks (rules in rules/injection.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_injection(path: Path, content: str) -> list[Finding]:
    return run_category("injection", path, content)
