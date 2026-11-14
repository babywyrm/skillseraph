"""Coverage guard: rule examples live in the rule YAML and must fire for real.

`examples.match` samples are checked twice: against the rule's own pattern
(what `skillseraph rules-test` does) and through the scanner, which catches
dead patterns the line-based engine or category dispatch never reaches.
"""

from importlib import resources
from pathlib import Path

import pytest

from skillseraph.checks import run_all_checks
from skillseraph.checks.mcp_servers import check_mcp_servers
from skillseraph.rules_engine import _load_all_rules, verify_rule_file

GENERIC = Path("AGENTS.md")
MCP = Path(".cursor/mcp.json")
JETBRAINS = Path(".idea/workspace.xml")
RULE_FILES = sorted(
    Path(str(entry)) for entry in resources.files("skillseraph.rules").iterdir() if entry.name.endswith(".yaml")
)
EXAMPLES = sorted(
    (rule["id"], category, sample)
    for category, rules in _load_all_rules().items()
    for rule in rules
    for sample in rule.get("examples", {}).get("match", [])
)


def test_every_rule_has_match_examples():
    with_examples = {rule_id for rule_id, _, _ in EXAMPLES}
    ids = {rule["id"] for rules in _load_all_rules().values() for rule in rules}
    assert sorted(ids - with_examples) == []


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_packaged_rule_files_pass_rules_test(path: Path):
    assert {r.rule_id: r.problems for r in verify_rule_file(path) if r.problems} == {}


@pytest.mark.parametrize(("rule_id", "category", "sample"), EXAMPLES)
def test_rule_example_fires_through_the_scanner(rule_id: str, category: str, sample: str):
    if category == "mcp_servers":
        findings = check_mcp_servers(MCP, sample)
    else:
        findings = run_all_checks(JETBRAINS if category == "jetbrains" else GENERIC, sample)
    assert any(f.check == rule_id for f in findings), f"{rule_id} did not fire; got {[f.check for f in findings]}"
