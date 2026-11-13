"""Agent permission modes: approval bypass, wildcard shell, sandbox off."""

from pathlib import Path

import pytest

from skillseraph.scanner import scan_directory

BYPASS = "agent_permission_bypass_mode"
SHELL = "agent_permission_wildcard_shell"
SANDBOX = "agent_permission_sandbox_off"


def _checks(tmp_path: Path, rel: str, body: str) -> dict[str, str]:
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return {
        f.check: f.severity.value
        for f in scan_directory(tmp_path).findings
        if f.check.startswith("agent_permission_")
    }


@pytest.mark.parametrize("rel", [".claude/settings.json", ".claude/settings.local.json"])
def test_claude_bypass_mode_and_wildcard_bash(tmp_path: Path, rel: str):
    checks = _checks(
        tmp_path,
        rel,
        '{\n  // team defaults\n  "permissions": {\n    "defaultMode": "bypassPermissions",\n'
        '    "allow": ["Read(src/**)", "Bash(*)"],\n  },\n}',
    )
    assert checks == {BYPASS: "high", SHELL: "high"}


@pytest.mark.parametrize("rule", ["Bash", "Bash()", "Bash(:*)", "Bash(bash:*)", "Bash(sh -c *)"])
def test_claude_unscoped_shell_rules(tmp_path: Path, rule: str):
    checks = _checks(tmp_path, ".claude/settings.json", f'{{"permissions": {{"allow": ["{rule}"]}}}}')
    assert SHELL in checks, rule


def test_claude_scoped_rules_and_default_mode_are_quiet(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".claude/settings.json",
        '{"permissions": {"defaultMode": "acceptEdits", '
        '"allow": ["Bash(npm run test *)", "Bash(git status:*)"], "deny": ["Bash(*)"]}}',
    )
    assert checks == {}


def test_codex_sandbox_off_and_never_approve(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".codex/config.toml",
        'approval_policy = "never"\n\n[profiles.fast]\nsandbox_mode = "danger-full-access"\n',
    )
    assert checks == {BYPASS: "medium", SANDBOX: "high"}


def test_codex_workspace_write_on_request_is_quiet(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".codex/config.toml",
        'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n',
    )
    assert checks == {}


def test_gemini_bare_shell_tool_allowed(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".gemini/settings.json",
        '{"tools": {"allowed": ["read_file", "run_shell_command"]}}',
    )
    assert checks == {SHELL: "high"}


def test_gemini_scoped_shell_tool_is_quiet(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".gemini/settings.json",
        '{"tools": {"allowed": ["run_shell_command(git status)", "run_shell_command(npm test)"]}}',
    )
    assert checks == {}


@pytest.mark.parametrize("rule", ["Shell(*)", "Shell(*:*)", "Shell(bash)", "Shell(zsh:*)"])
def test_cursor_cli_wildcard_shell(tmp_path: Path, rule: str):
    checks = _checks(tmp_path, ".cursor/cli.json", f'{{"permissions": {{"allow": ["{rule}"]}}}}')
    assert checks == {SHELL: "high"}, rule


def test_cursor_cli_scoped_shell_is_quiet(tmp_path: Path):
    checks = _checks(
        tmp_path,
        ".cursor/cli.json",
        '{"permissions": {"allow": ["Shell(git)", "Shell(npm:test)"], "deny": ["Shell(*)"]}}',
    )
    assert checks == {}


def test_same_keys_outside_agent_configs_are_quiet(tmp_path: Path):
    checks = _checks(
        tmp_path,
        "docs/example.json",
        '{"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}}',
    )
    assert checks == {}


def test_audit_local_reads_user_permission_files(tmp_path: Path):
    from skillseraph.local_audit import audit_local_ide_configs

    files = {
        ".claude/settings.json": '{"permissions": {"defaultMode": "bypassPermissions"}}',
        ".codex/config.toml": 'sandbox_mode = "danger-full-access"\n',
        ".gemini/settings.json": '{"tools": {"allowed": ["run_shell_command"]}}',
        ".cursor/cli-config.json": '{"permissions": {"allow": ["Shell(*)"]}}',
    }
    for rel, body in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(body)
    hits = {
        (f.path.relative_to(tmp_path).as_posix(), f.check)
        for f in audit_local_ide_configs(home=tmp_path).findings
        if f.check.startswith("agent_permission_")
    }
    assert hits == {
        (".claude/settings.json", BYPASS),
        (".codex/config.toml", SANDBOX),
        (".gemini/settings.json", SHELL),
        (".cursor/cli-config.json", SHELL),
    }
