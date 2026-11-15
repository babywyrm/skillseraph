"""Watch mode gates every scan and sees the files a normal scan sees."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from skillseraph import watcher
from skillseraph.cli import main
from skillseraph.models import Finding, ScanResult, Severity


def test_unsupported_flags_are_refused(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, [str(tmp_path), "--watch", "--baseline", "b.json"])
    assert result.exit_code == 2
    assert "--baseline" in result.output


def test_gate_rechecks_when_count_is_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def result(severity: Severity) -> ScanResult:
        finding = Finding(path=tmp_path / "AGENTS.md", check="c", severity=severity, title="t", detail="d")
        return ScanResult(target=tmp_path, findings=[finding])

    scans = iter([result(Severity.LOW), result(Severity.CRITICAL)])
    monkeypatch.setattr(watcher, "scan_directory", lambda *a, **k: next(scans))
    monkeypatch.setattr(watcher, "_poll_changes", lambda *a: [tmp_path / "AGENTS.md"])
    monkeypatch.setattr(watcher.time, "sleep", lambda _: None)
    with pytest.raises(SystemExit) as exc:
        watcher.watch_and_scan(tmp_path, fail_on="high", quiet=True)
    assert exc.value.code == 1


def test_poll_sees_files_under_directory_patterns(tmp_path: Path) -> None:
    rule = tmp_path / ".cursor" / "rules" / "a.mdc"
    rule.parent.mkdir(parents=True)
    rule.write_text("Use tabs.\n")
    assert rule in watcher._poll_changes(tmp_path, {}, None, True)
