"""Exfiltration checks (rules in rules/exfiltration.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_exfiltration(path: Path, content: str) -> list[Finding]:
    return run_category("exfiltration", path, content)
