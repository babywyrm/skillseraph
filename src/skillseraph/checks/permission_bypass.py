"""Permission/sandbox bypass checks.

Line rules live in rules/permission_bypass.yaml. Agent clients also store
permission modes as structured settings (Claude Code, Codex, Gemini CLI,
Cursor CLI, Amazon Q, Aider), which get a parsed pass so evidence is the
exact key and value.
"""

from __future__ import annotations

import fnmatch
import re
import tomllib
from pathlib import Path

import yaml

from ..models import Finding, Severity
from ..rules_engine import run_category
from . import is_amazonq_agent, load_jsonc
from .mcp_servers import _SHELLS

_RULE = re.compile(r"^\s*(\w+)\s*(?:\((.*)\))?\s*$", re.DOTALL)


def check_permission_bypass(path: Path, content: str) -> list[Finding]:
    return run_category("permission_bypass", path, content) + _agent_permissions(path, content)


def _finding(path: Path, check: str, severity: Severity, title: str, detail: str, evidence: str) -> Finding:
    return Finding(
        path=path,
        check=check,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence[:200],
        taxonomy_id="MCP-T09",
        atlas_id="J1",
    )


def _unscoped_shell_rules(rules: object, tools: set[str]) -> list[str]:
    """Allow rules that let a shell tool run any command."""
    if not isinstance(rules, list):
        return []
    hits = []
    for rule in rules:
        match = _RULE.match(rule) if isinstance(rule, str) else None
        if not match or match.group(1) not in tools:
            continue
        spec = (match.group(2) or "").strip()
        base = re.split(r"[\s:]", spec, maxsplit=1)[0]
        if base in {"", "*"} or Path(base).name in _SHELLS:
            hits.append(rule)
    return hits


def _section(data: object, key: str) -> dict[str, object]:
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def _shell_finding(path: Path, key: str, rules: list[str]) -> list[Finding]:
    if not rules:
        return []
    return [_finding(
        path,
        "agent_permission_wildcard_shell",
        Severity.HIGH,
        "Agent may run any shell command without approval",
        "An allow rule names a shell tool with no command, a wildcard, or a shell "
        "interpreter, so every command skips the approval prompt.",
        f"{key}: {', '.join(rules[:5])}",
    )]


def _agent_permissions(path: Path, content: str) -> list[Finding]:
    name, parts = path.name, path.parts
    if name == "config.toml" and path.parent.name == ".codex":
        return _codex(path, content)
    if name in {"settings.json", "settings.local.json"} and ".claude" in parts:
        return _claude(path, load_jsonc(content))
    if name == "settings.json" and path.parent.name == ".gemini":
        rules = _unscoped_shell_rules(_section(load_jsonc(content), "tools").get("allowed"), {"run_shell_command", "ShellTool"})
        return _shell_finding(path, "tools.allowed", rules)
    if name in {"cli.json", "cli-config.json"} and path.parent.name == ".cursor":
        rules = _unscoped_shell_rules(_section(load_jsonc(content), "permissions").get("allow"), {"Shell"})
        return _shell_finding(path, "permissions.allow", rules)
    if is_amazonq_agent(path):
        data = load_jsonc(content)
        allowed = data.get("allowedTools") if isinstance(data, dict) else None
        rules = [
            r for r in allowed if isinstance(r, str) and _amazonq_allows_shell(r)
        ] if isinstance(allowed, list) else []
        return _shell_finding(path, "allowedTools", rules)
    if name == ".aider.conf.yml":
        return _aider(path, content)
    return []


def _amazonq_allows_shell(rule: str) -> bool:
    """Amazon Q allowedTools are globs; ``@builtin`` allows every native tool."""
    if rule == "@builtin":
        return True
    return fnmatch.fnmatchcase("execute_bash", rule.removeprefix("@builtin/"))


def _aider(path: Path, content: str) -> list[Finding]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict) or data.get("yes-always") is not True:
        return []
    return [_finding(
        path,
        "agent_permission_bypass_mode",
        Severity.HIGH,
        "Aider answers yes to every confirmation",
        "yes-always approves every prompt, including running suggested shell commands "
        "and adding files or URLs to the chat.",
        "yes-always=true",
    )]


def _claude(path: Path, data: object) -> list[Finding]:
    permissions = _section(data, "permissions")
    findings = []
    if permissions.get("defaultMode") == "bypassPermissions":
        findings.append(_finding(
            path,
            "agent_permission_bypass_mode",
            Severity.HIGH,
            "Claude Code permission prompts are bypassed",
            "defaultMode bypassPermissions skips every approval. Recent releases ignore it in "
            "project files, but user settings and older releases honor it.",
            "permissions.defaultMode=bypassPermissions",
        ))
    findings += _shell_finding(path, "permissions.allow", _unscoped_shell_rules(permissions.get("allow"), {"Bash"}))
    return findings


def _codex(path: Path, content: str) -> list[Finding]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []
    tables = [("", data)] + [(f"profiles.{k}.", v) for k, v in _section(data, "profiles").items() if isinstance(v, dict)]
    never = [f"{prefix}approval_policy" for prefix, t in tables if t.get("approval_policy") == "never"]
    open_ = [f"{prefix}sandbox_mode" for prefix, t in tables if t.get("sandbox_mode") == "danger-full-access"]
    findings = []
    if never:
        findings.append(_finding(
            path,
            "agent_permission_bypass_mode",
            Severity.MEDIUM,
            "Codex never asks for approval",
            "approval_policy never runs every action unprompted; only the sandbox limits it.",
            f"{', '.join(never)}=never",
        ))
    if open_:
        findings.append(_finding(
            path,
            "agent_permission_sandbox_off",
            Severity.HIGH,
            "Codex sandbox is disabled",
            "danger-full-access gives the agent unrestricted file and network access.",
            f"{', '.join(open_)}=danger-full-access",
        ))
    return findings
