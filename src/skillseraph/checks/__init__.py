"""Check modules — each detects a category of agent config attack."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding


def load_jsonc(content: str) -> object | None:
    """Parse JSON that may carry // and /* */ comments and trailing commas."""
    out: list[str] = []
    i, n, in_string = 0, len(content), False
    while i < n:
        ch = content[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(content[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif content.startswith("//", i):
            i = content.find("\n", i)
            if i == -1:
                break
            continue
        elif content.startswith("/*", i):
            end = content.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        elif ch in "]}":
            while out and out[-1].isspace():
                out.pop()
            if out and out[-1] == ",":
                out.pop()
            out.append(ch)
        else:
            out.append(ch)
        i += 1
    try:
        parsed: object = json.loads("".join(out))
    except json.JSONDecodeError:
        return None
    return parsed


def run_all_checks(path: Path, content: str, line_offset: int = 0) -> list[Finding]:
    """Run all check categories against a file's content."""
    from .approver_manipulation import check_approver_manipulation
    from .authority_fabrication import check_authority_fabrication
    from .automation_triggers import check_automation_triggers
    from .breakglass import check_breakglass
    from .config_inheritance import check_config_inheritance
    from .encoding import check_encoding
    from .exfiltration import check_exfiltration
    from .extensions import check_extension_manifest
    from .ide_integrations import check_ide_integrations
    from .injection import check_injection
    from .jetbrains import check_jetbrains
    from .lifecycle import check_lifecycle
    from .mcp_servers import check_mcp_servers
    from .monitoring_bypass import check_monitoring_bypass
    from .permission_bypass import check_permission_bypass
    from .persistence import check_persistence
    from .runtime_bypass import check_runtime_bypass
    from .runtime_escape import check_runtime_escape
    from .skill_invocation import check_skill_invocation
    from .supply_chain_trust import check_supply_chain_trust
    from .suppression import check_suppression
    from .tool_abuse import check_tool_abuse
    from .urls import check_urls

    findings: list[Finding] = []
    for checker in [
        check_injection,
        check_exfiltration,
        check_permission_bypass,
        check_encoding,
        check_urls,
        check_suppression,
        check_persistence,
        check_tool_abuse,
        check_authority_fabrication,
        check_runtime_bypass,
        check_breakglass,
        check_automation_triggers,
        check_config_inheritance,
        check_mcp_servers,
        check_skill_invocation,
        check_ide_integrations,
        check_extension_manifest,
        check_lifecycle,
        check_jetbrains,
        check_supply_chain_trust,
        check_runtime_escape,
        check_approver_manipulation,
        check_monitoring_bypass,
    ]:
        findings.extend(checker(path, content))
    return findings
