"""Check modules — each detects a category of agent config attack."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding


def run_all_checks(path: Path, content: str, line_offset: int = 0) -> list[Finding]:
    """Run all check categories against a file's content."""
    from .injection import check_injection
    from .exfiltration import check_exfiltration
    from .permission_bypass import check_permission_bypass
    from .encoding import check_encoding
    from .urls import check_urls
    from .suppression import check_suppression
    from .persistence import check_persistence
    from .tool_abuse import check_tool_abuse
    from .authority_fabrication import check_authority_fabrication
    from .runtime_bypass import check_runtime_bypass
    from .breakglass import check_breakglass
    from .automation_triggers import check_automation_triggers
    from .config_inheritance import check_config_inheritance
    from .mcp_servers import check_mcp_servers

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
    ]:
        findings.extend(checker(path, content))
    return findings
