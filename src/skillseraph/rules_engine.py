"""YAML-driven rules engine.

Detection patterns live in `rules/*.yaml` as data, not code. Each rule file has
a `category` and a list of `rules`, where each rule is:

    - id: <stable check name>
      pattern: <python regex, case-insensitive>
      severity: critical|high|medium|low
      title: <human-readable finding title>
      taxonomy_id: <OWASP MCP / MCP-T id>
      atlas_id: <Attack Path Atlas domain id>

The engine compiles all rules once and runs them line-by-line. Check modules
delegate to `run_category()` so the regex catalogue stays fully data-driven.
"""

from __future__ import annotations

import functools
import re
from importlib import resources
from pathlib import Path

import yaml

from .models import Finding, Severity


@functools.lru_cache(maxsize=1)
def _load_all_rules() -> dict[str, list[dict]]:
    """Load and cache every rule file, keyed by category."""
    catalogue: dict[str, list[dict]] = {}
    rules_pkg = resources.files("skillseraph.rules")
    for entry in rules_pkg.iterdir():
        if not entry.name.endswith((".yaml", ".yml")):
            continue
        data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
        category = data.get("category", entry.name.rsplit(".", 1)[0])
        rules = data.get("rules", [])
        for rule in rules:
            rule["_compiled"] = re.compile(rule["pattern"], re.IGNORECASE)
            rule.setdefault("category", category)
        catalogue.setdefault(category, []).extend(rules)
    return catalogue


def available_categories() -> list[str]:
    return sorted(_load_all_rules().keys())


def run_category(category: str, path: Path, content: str) -> list[Finding]:
    """Run all rules in a category against file content."""
    rules = _load_all_rules().get(category, [])
    if not rules:
        return []

    findings: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        for rule in rules:
            if rule["_compiled"].search(line):
                findings.append(Finding(
                    path=path,
                    check=rule["id"],
                    severity=Severity(rule["severity"]),
                    title=rule["title"],
                    detail=f"Line {line_num}: {line.strip()[:120]}",
                    line=line_num,
                    evidence=line.strip()[:200],
                    taxonomy_id=rule.get("taxonomy_id", ""),
                    atlas_id=rule.get("atlas_id", ""),
                ))
    return findings
