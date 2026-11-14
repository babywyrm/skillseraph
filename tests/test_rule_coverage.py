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
RULE_FILES = sorted(
    Path(str(entry)) for entry in resources.files("skillseraph.rules").iterdir() if entry.name.endswith(".yaml")
)
EXAMPLES = sorted(
    (rule["id"], category, sample)
    for category, rules in _load_all_rules().items()
    for rule in rules
    for sample in rule.get("examples", {}).get("match", [])
)


def test_every_yaml_rule_is_exercised_by_a_test():
    # ponytail: a test naming the id is the bar for rules without examples, not
    # proof they fire; upgrade by giving every rule examples.match in its YAML.
    tests_text = "\n".join(p.read_text() for p in Path(__file__).parent.glob("test_*.py"))
    with_examples = {rule_id for rule_id, _, _ in EXAMPLES}
    ids = {rule["id"] for rules in _load_all_rules().values() for rule in rules}
    assert sorted(i for i in ids - with_examples if i not in tests_text) == []


def test_example_count_only_grows():
    assert len({rule_id for rule_id, _, _ in EXAMPLES}) >= 22


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.name)
def test_packaged_examples_agree_with_their_patterns(path: Path):
    problems = {
        r.rule_id: r.problems
        for r in verify_rule_file(path)
        if [p for p in r.problems if p != "needs at least one examples.match sample"]
    }
    assert problems == {}


@pytest.mark.parametrize(("rule_id", "category", "sample"), EXAMPLES)
def test_rule_example_fires_through_the_scanner(rule_id: str, category: str, sample: str):
    if category == "mcp_servers":
        findings = check_mcp_servers(MCP, sample)
    else:
        findings = run_all_checks(GENERIC, sample)
    assert any(f.check == rule_id for f in findings), f"{rule_id} did not fire; got {[f.check for f in findings]}"
