"""Atlas J3 — Automation trigger abuse checks (rules in rules/automation_triggers.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_automation_triggers(path: Path, content: str) -> list[Finding]:
    return run_category("automation_triggers", path, content)
