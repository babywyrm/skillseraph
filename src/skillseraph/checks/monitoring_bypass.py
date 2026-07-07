"""Monitoring-exception blind-spot checks (rules in rules/monitoring_bypass.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_monitoring_bypass(path: Path, content: str) -> list[Finding]:
    return run_category("monitoring_bypass", path, content)
