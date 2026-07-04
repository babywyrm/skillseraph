"""Locks in the per-rule confidence tuning decisions across all rule packs."""

import pytest

from skillseraph.rules_engine import _load_all_rules


def _confidence_by_id() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for rules in _load_all_rules().values():
        for rule in rules:
            mapping[rule["id"]] = rule.get("confidence", "high")
    return mapping


# Broad blobs / generic role markers: prone to benign matches.
LOW = ["fake_role_claim", "base64_blob", "hex_blob"]

# Natural-language instruction heuristics: usually malicious, sometimes benign.
MEDIUM = [
    "persona_hijack",
    "hypothetical_framing",
    "sleeper_conditional_trigger",
    "sleeper_selective_disclosure",
    "env_secret_access",
    "stealth_operation",
    "breakglass_reference",
    "validation_skip",
    "privilege_request",
    "persistent_behavior",
    "permanent_instruction",
    "false_trust_assertion",
    "skill_invocation_override",
    "ide_untrusted_extension_recommendation",
]

# Deterministic / structural markers: must stay high.
HIGH = [
    "prompt_injection_override",
    "token_boundary_injection",
    "remote_bootstrap",
    "eval_atob_pattern",
    "j5_remote_config_fetch",
    "mcp_server_stdio_arbitrary_command",
    "jetbrains_runconfig_remote_fetch",
    "supply_chain_registry_confusion",
]


@pytest.mark.parametrize("rule_id", LOW)
def test_low_confidence_rules(rule_id):
    assert _confidence_by_id()[rule_id] == "low"


@pytest.mark.parametrize("rule_id", MEDIUM)
def test_medium_confidence_rules(rule_id):
    assert _confidence_by_id()[rule_id] == "medium"


@pytest.mark.parametrize("rule_id", HIGH)
def test_high_confidence_rules(rule_id):
    assert _confidence_by_id()[rule_id] == "high"


def test_all_confidence_values_are_valid():
    valid = {"low", "medium", "high"}
    invalid = {rid: c for rid, c in _confidence_by_id().items() if c not in valid}
    assert invalid == {}
