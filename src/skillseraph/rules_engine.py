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
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import NotRequired, TypedDict

import yaml

from .models import Finding, Severity


class Rule(TypedDict):
    id: str
    pattern: str
    severity: str
    title: str
    category: str
    _compiled: re.Pattern[str]
    taxonomy_id: NotRequired[str]
    atlas_id: NotRequired[str]
    confidence: NotRequired[str]


@functools.lru_cache(maxsize=1)
def _load_all_rules() -> dict[str, list[Rule]]:
    """Load and cache every rule file, keyed by category."""
    catalogue: dict[str, list[Rule]] = {}
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


class RuleFileError(ValueError):
    """A rule file cannot be read or has no top-level ``rules`` list."""


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    problems: tuple[str, ...]
    examples: int


_RULE_ID = re.compile(r"[a-z0-9_]+")
_SEVERITIES = tuple(s.value for s in Severity)
_CONFIDENCES = ("low", "medium", "high")


def packaged_rule_ids() -> dict[str, Path]:
    """Rule id -> resolved path of the packaged rule file that defines it."""
    owners: dict[str, Path] = {}
    for entry in resources.files("skillseraph.rules").iterdir():
        if entry.name.endswith((".yaml", ".yml")):
            data = yaml.safe_load(entry.read_text(encoding="utf-8")) or {}
            owners.update((rule["id"], Path(str(entry)).resolve()) for rule in data.get("rules", []))
    return owners


def _samples(examples: dict[object, object], key: str, problems: list[str]) -> list[str]:
    value = examples.get(key, [])
    if isinstance(value, list) and all(isinstance(s, str) for s in value):
        return value
    problems.append(f"examples.{key} must be a list of strings")
    return []


def _hits(pattern: re.Pattern[str], sample: str) -> bool:
    """Same semantics as run_category: any single line matches."""
    return any(pattern.search(line) for line in sample.splitlines() or [""])


def _verify_rule(rule: object, index: int, seen: set[str], owners: dict[str, Path], own: Path) -> RuleResult:
    if not isinstance(rule, dict):
        return RuleResult(f"rules[{index}]", ("rule must be a mapping",), 0)
    rule_id = rule.get("id")
    name = rule_id if isinstance(rule_id, str) else f"rules[{index}]"
    problems: list[str] = []
    if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
        problems.append("id must be lowercase letters, digits, and underscores")
    elif rule_id in seen:
        problems.append("duplicate id in this file")
    elif owners.get(rule_id, own) != own:
        problems.append(f"id already used by packaged rule {owners[rule_id].name}")
    seen.add(name)
    if not isinstance(rule.get("title"), str) or not rule["title"].strip():
        problems.append("title must be a non-empty string")
    if rule.get("severity") not in _SEVERITIES:
        problems.append(f"severity must be one of {', '.join(_SEVERITIES)}")
    if rule.get("confidence", "high") not in _CONFIDENCES:
        problems.append(f"confidence must be one of {', '.join(_CONFIDENCES)}")
    compiled: re.Pattern[str] | None = None
    pattern = rule.get("pattern")
    if not isinstance(pattern, str) or not pattern:
        problems.append("pattern must be a non-empty string")
    else:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            problems.append(f"pattern does not compile: {exc}")
    examples = rule.get("examples", {})
    if not isinstance(examples, dict):
        problems.append("examples must be a mapping with match / no_match lists")
        examples = {}
    matches = _samples(examples, "match", problems)
    misses = _samples(examples, "no_match", problems)
    if not matches:
        problems.append("needs at least one examples.match sample")
    if compiled is not None:
        problems += [f"match example {n} does not match" for n, s in enumerate(matches, 1) if not _hits(compiled, s)]
        problems += [f"no_match example {n} matches" for n, s in enumerate(misses, 1) if _hits(compiled, s)]
    return RuleResult(name, tuple(problems), len(matches) + len(misses))


def verify_rule_file(path: Path, owners: dict[str, Path] | None = None) -> list[RuleResult]:
    """Check each rule's shape and run its examples through its own pattern.

    *owners* maps packaged rule ids to their files; an id defined by a
    different file is a collision, so a packaged file may test its own ids.
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RuleFileError(f"cannot read rule file {path}: {exc}") from exc
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list):
        raise RuleFileError(f"{path} needs a top-level rules list")
    seen: set[str] = set()
    owners = packaged_rule_ids() if owners is None else owners
    return [_verify_rule(rule, i, seen, owners, path.resolve()) for i, rule in enumerate(rules)]


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
                    confidence=rule.get("confidence", "high"),
                ))
    return findings
