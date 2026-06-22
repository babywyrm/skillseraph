"""Generate a NullfieldPolicy YAML from scan findings.

Closes the scan-to-enforce loop: skillseraph detects dangerous patterns in agent
configs, then this module emits a nullfield policy that DENYs the corresponding
MCP tool calls at runtime.

Usage (CLI):
    skillseraph . --generate-policy policy.yaml

The generated policy uses a tiered model:
  - Tools mentioned in critical/high findings → DENY
  - Tools mentioned in medium findings → HOLD (human approval)
  - Everything else → default DENY (safe-by-default)
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import ScanResult, Severity

TOOL_INDICATORS = {
    "exfiltration": ["egress.fetch_url", "gateway.fetch_content"],
    "tool_abuse": ["shellwrap.exec", "subprocess.invoke_worker"],
    "runtime_bypass": ["hallucination.execute_plan"],
    "permission_bypass": ["platform.execute_privileged_op", "platform.mint_token"],
    "persistence": ["shadow.register_webhook", "config.update_system_prompt"],
    "injection": ["config.update_system_prompt", "rag.add_document"],
    "authority_fabrication": ["config.update_system_prompt"],
    "breakglass": ["platform.execute_privileged_op"],
    "automation_triggers": ["chain.delegate_task", "subchain.spawn_agent"],
    "config_inheritance": ["config.update_system_prompt"],
}


def generate_policy(
    result: ScanResult,
    name: str = "skillseraph-generated",
    namespace: str = "default",
    selector_labels: dict[str, str] | None = None,
) -> dict:
    """Generate a NullfieldPolicy dict from scan findings."""
    deny_tools: set[str] = set()
    hold_tools: set[str] = set()

    for finding in result.findings:
        category = finding.check.split("_")[0] if "_" in finding.check else finding.check
        tools = TOOL_INDICATORS.get(category, [])
        for cat, tool_list in TOOL_INDICATORS.items():
            if cat in finding.check:
                tools = tool_list
                break

        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            deny_tools.update(tools)
        elif finding.severity == Severity.MEDIUM:
            hold_tools.update(tools)

    hold_tools -= deny_tools

    rules = []
    if deny_tools:
        rules.append({
            "action": "DENY",
            "mcpMethod": "tools/call",
            "toolNames": sorted(deny_tools),
            "reason": "skillseraph: critical/high findings in agent config",
        })
    if hold_tools:
        rules.append({
            "action": "HOLD",
            "mcpMethod": "tools/call",
            "toolNames": sorted(hold_tools),
            "hold": {"timeout": "5m", "onTimeout": "DENY"},
            "reason": "skillseraph: medium findings — requires human approval",
        })
    rules.append({
        "action": "DENY",
        "mcpMethod": "tools/call",
        "toolNames": ["*"],
        "reason": "default deny (skillseraph safe-by-default policy)",
    })

    policy = {
        "apiVersion": "nullfield.io/v1alpha1",
        "kind": "NullfieldPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": {
                "skillseraph.io/generated-from": str(result.target),
                "skillseraph.io/findings-count": str(len(result.findings)),
            },
        },
        "spec": {
            "selector": {"matchLabels": selector_labels or {"app": "agent"}},
            "rules": rules,
            "audit": {"logLevel": "FULL"},
        },
    }
    return policy


def write_policy(result: ScanResult, path: Path, **kwargs) -> int:
    """Generate and write a NullfieldPolicy YAML file. Returns finding count."""
    policy = generate_policy(result, **kwargs)
    path.write_text(yaml.dump(policy, default_flow_style=False, sort_keys=False))
    return len(result.findings)
