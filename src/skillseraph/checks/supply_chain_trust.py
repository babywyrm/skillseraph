"""Skill/plugin source trust & auto-deploy checks (rules in rules/supply_chain_trust.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_supply_chain_trust(path: Path, content: str) -> list[Finding]:
    return run_category("supply_chain_trust", path, content)
