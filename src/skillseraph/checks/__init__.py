"""Check modules — each detects a category of agent config attack."""

from __future__ import annotations

import json
import re
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


_SECRET_WORD = (
    r"(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key"
    r"|credential|authorization)"
)
_SECRET_KEY_VALUE = re.compile(
    rf"(?i)(?<![\w.-])([\"']?[\w.-]*{_SECRET_WORD}[\w.-]*[\"']?\s*[:=]\s*[\"']?)"
    r"(?!\$|\{env:|<redacted>)(?!(?:Bearer|Basic|Token)\s)([^\s\"',}\]]{4,})"
)
_SECRET_FLAG = re.compile(
    rf"(?i)(--?[\w-]*{_SECRET_WORD}[\w-]*[\"']?(?:\s*,\s*[\"']|\s+))"
    r"(?!\$|<redacted>|-)([^\s\"',}\]]{4,})"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer|Basic|Token)\s+(?!\$)[\w.~+/=-]{6,}")
_URL_USERINFO = re.compile(r"(https?://)[^/\s\"'@]+@")
TOKEN_SHAPES = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}|sk-[\w-]{16,}|xox[abprs]-[\w-]{10,}"
    r"|AKIA[0-9A-Z]{16}|glpat-[\w-]{20,})"
)


def redact(text: str) -> str:
    """Strip secret values from report text; key names and ${VAR} references stay."""
    # ponytail: key-name and token-shape heuristics; an unusually named secret can still pass.
    text = _URL_USERINFO.sub(r"\1", text)
    text = TOKEN_SHAPES.sub("<redacted>", text)
    text = _AUTH_SCHEME.sub(r"\1 <redacted>", text)
    text = _SECRET_FLAG.sub(r"\1<redacted>", text)
    return _SECRET_KEY_VALUE.sub(r"\1<redacted>", text)


def is_amazonq_agent(path: Path) -> bool:
    """Amazon Q agent config: default.json or cli-agents/*.json, repo or ~/.aws."""
    parent, grandparent = path.parent.name, path.parent.parent.name
    if path.suffix != ".json":
        return False
    if path.name == "default.json" and (parent == ".amazonq" or (parent == "amazonq" and grandparent == ".aws")):
        return True
    return parent == "cli-agents" and grandparent in {".amazonq", "amazonq"}


def run_all_checks(path: Path, content: str, line_offset: int = 0) -> list[Finding]:
    """Run all check categories against a file's content."""
    from .a2a import check_a2a_card
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
        check_a2a_card,
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
