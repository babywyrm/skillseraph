"""Tests for Atlas J3 (automation triggers) and J5 (config inheritance) rules."""

from pathlib import Path

from skillseraph.scanner import scan_file


FIXTURES = Path(__file__).parent / "fixtures"


def test_j3_wildcard_trigger():
    findings = scan_file(FIXTURES / "j3_broad_automation.yml")
    j3_ids = [f.atlas_id for f in findings if f.atlas_id and f.atlas_id.startswith("J3")]
    assert len(j3_ids) >= 1, f"Expected J3 findings, got: {[f.check for f in findings]}"


def test_j3_shell_exec_in_automation():
    findings = scan_file(FIXTURES / "j3_broad_automation.yml")
    checks = [f.check for f in findings]
    assert any("shell_exec" in c or "curl" in c.lower() or "tool_abuse" in c for c in checks), \
        f"Expected shell-exec or tool-abuse finding: {checks}"


def test_j5_parent_traversal():
    findings = scan_file(FIXTURES / "j5_parent_include.md")
    j5_ids = [f for f in findings if f.atlas_id and f.atlas_id.startswith("J5")]
    assert len(j5_ids) >= 1, f"Expected J5 findings, got: {[f.check for f in findings]}"


def test_j5_remote_fetch():
    findings = scan_file(FIXTURES / "j5_parent_include.md")
    remote = [f for f in findings if "remote" in f.title.lower() or "url" in f.check.lower()]
    assert len(remote) >= 1, f"Expected remote-fetch finding: {[(f.check, f.title) for f in findings]}"
