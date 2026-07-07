"""Automated-approver / LLM-judge manipulation checks (rules in rules/approver_manipulation.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_approver_manipulation(path: Path, content: str) -> list[Finding]:
    return run_category("approver_manipulation", path, content)
