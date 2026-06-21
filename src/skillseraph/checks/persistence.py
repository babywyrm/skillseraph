"""Persistence checks (rules in rules/persistence.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_persistence(path: Path, content: str) -> list[Finding]:
    return run_category("persistence", path, content)
