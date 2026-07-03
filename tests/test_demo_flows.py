"""Tests for built-in demo fixture and smoke-test flows."""

from pathlib import Path

from click.testing import CliRunner

from skillseraph.cli import main


def test_demo_fixture_creates_safe_repo_and_home_fixture(tmp_path: Path):
    fixture_root = tmp_path / "fixture"

    result = CliRunner().invoke(main, ["demo-fixture", "--output", str(fixture_root)])

    assert result.exit_code == 0
    assert (fixture_root / "repo" / ".vscode" / "tasks.json").exists()
    assert (fixture_root / "repo" / ".cursor" / "mcp.json").exists()
    assert (
        fixture_root
        / "home"
        / "Library"
        / "Application Support"
        / "Code"
        / "User"
        / "settings.json"
    ).exists()
    assert "Demo fixture written" in result.output


def test_demo_fixture_refuses_non_empty_output_without_force(tmp_path: Path):
    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    (fixture_root / "keep.txt").write_text("do not overwrite")

    result = CliRunner().invoke(main, ["demo-fixture", "--output", str(fixture_root)])

    assert result.exit_code != 0
    assert "Refusing to write into non-empty directory" in result.output
    assert (fixture_root / "keep.txt").read_text() == "do not overwrite"


def test_smoke_test_runs_fixture_scans_and_cleans_up():
    result = CliRunner().invoke(main, ["smoke-test"])

    assert result.exit_code == 0
    assert "Smoke test passed" in result.output
    assert "ide_task_remote_shell_pipe" in result.output
    assert "mcp_server_stdio_arbitrary_command" in result.output
    assert "ide_runtime_preload" in result.output
