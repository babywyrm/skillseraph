"""JetBrains IDE project config checks (rules in rules/jetbrains.yaml)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def _is_jetbrains_file(path: Path) -> bool:
    return ".idea/" in path.as_posix() or path.suffix == ".iml"


def check_jetbrains(path: Path, content: str) -> list[Finding]:
    if not _is_jetbrains_file(path):
        return []
    return run_category("jetbrains", path, content)
