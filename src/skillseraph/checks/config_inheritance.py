"""Atlas J5 — Config inheritance escalation checks (rules in rules/config_inheritance.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_config_inheritance(path: Path, content: str) -> list[Finding]:
    return run_category("config_inheritance", path, content)
