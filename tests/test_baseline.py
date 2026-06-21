"""Tests for baseline / allowlist support."""

from pathlib import Path

from skillseraph.baseline import apply_baseline, fingerprint, load_baseline, save_baseline
from skillseraph.models import Finding, Platform, ScanResult, Severity


def _result(tmp_path: Path) -> ScanResult:
    f = Finding(
        path=tmp_path / "AGENTS.md",
        check="jailbreak_language",
        severity=Severity.CRITICAL,
        title="Jailbreak",
        detail="Line 3: DAN mode",
        line=3,
        evidence="DAN mode activated",
    )
    return ScanResult(target=tmp_path, findings=[f], files_scanned=1,
                      platforms_detected=[Platform.GENERIC])


def test_fingerprint_is_line_independent(tmp_path):
    a = Finding(path=tmp_path / "x.md", check="c", severity=Severity.HIGH,
                title="t", detail="d", line=1, evidence="same evidence")
    b = Finding(path=tmp_path / "x.md", check="c", severity=Severity.HIGH,
                title="t", detail="d", line=99, evidence="same evidence")
    assert fingerprint(a, tmp_path) == fingerprint(b, tmp_path)


def test_save_and_load_roundtrip(tmp_path):
    result = _result(tmp_path)
    bpath = tmp_path / "baseline.json"
    count = save_baseline(result, bpath)
    assert count == 1
    fps = load_baseline(bpath)
    assert len(fps) == 1


def test_apply_baseline_suppresses(tmp_path):
    result = _result(tmp_path)
    bpath = tmp_path / "baseline.json"
    save_baseline(result, bpath)
    filtered = apply_baseline(result, load_baseline(bpath))
    assert len(filtered.findings) == 0


def test_load_missing_baseline_is_empty(tmp_path):
    assert load_baseline(tmp_path / "nope.json") == set()
