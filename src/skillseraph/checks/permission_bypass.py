"""Permission/sandbox bypass checks (rules in rules/permission_bypass.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_permission_bypass(path: Path, content: str) -> list[Finding]:
    return run_category("permission_bypass", path, content)
