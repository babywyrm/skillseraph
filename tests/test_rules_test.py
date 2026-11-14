"""`skillseraph rules-test FILE...` checks contributed rules against their own examples."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from skillseraph.cli import main

GOOD = """\
category: contributed
rules:
  - id: demo_wipe_disk
    pattern: 'rm\\s+-rf\\s+/(\\s|$)'
    severity: critical
    title: "Wipes the root filesystem"
    examples:
      match:
        - "rm -rf /"
        - "first line\\nthen rm  -rf / now"
      no_match:
        - "rm -rf ./build"
"""


def _rules(tmp_path: Path, body: str, name: str = "rules.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def _run(*args: str):
    return CliRunner().invoke(main, ["rules-test", *args])


def test_good_rule_file_passes(tmp_path: Path):
    result = _run(str(_rules(tmp_path, GOOD)))
    assert result.exit_code == 0, result.output
    assert "demo_wipe_disk (3 examples)" in result.output
    assert "1 rule(s) passed, 0 failed" in result.output


def _broken(**fields: str) -> str:
    rule = {
        "id": "demo_rule", "pattern": "'evil'", "severity": "high", "title": '"t"',
        "examples": '{match: ["evil"]}', **fields,
    }
    lines = "".join(f"    {k}: {v}\n" for k, v in rule.items() if v != "-")
    return "rules:\n  - " + lines[4:]


@pytest.mark.parametrize(
    ("fields", "problem"),
    [
        ({"examples": '{match: ["good"]}'}, "match example 1 does not match"),
        ({"examples": '{match: ["evil"], no_match: ["evil twin"]}'}, "no_match example 1 matches"),
        ({"examples": "-"}, "needs at least one examples.match sample"),
        ({"pattern": "'(unclosed'"}, "pattern does not compile"),
        ({"severity": "urgent"}, "severity must be one of"),
        ({"confidence": "sure"}, "confidence must be one of"),
        ({"title": "-"}, "title must be a non-empty string"),
        ({"id": "Bad-Id"}, "id must be lowercase"),
        ({"id": "prompt_injection_override"}, "id already used by packaged rule injection.yaml"),
        ({"examples": '{match: "evil"}'}, "examples.match must be a list of strings"),
    ],
)
def test_broken_rules_fail(tmp_path: Path, fields: dict[str, str], problem: str):
    result = _run(str(_rules(tmp_path, _broken(**fields))))
    assert result.exit_code == 1, result.output
    assert problem in result.output
    assert "0 rule(s) passed, 1 failed" in result.output


def test_packaged_file_name_does_not_exempt_a_collision(tmp_path: Path):
    path = _rules(tmp_path, _broken(id="prompt_injection_override"), "injection.yaml")
    result = _run(str(path))
    assert result.exit_code == 1
    assert "id already used by packaged rule injection.yaml" in result.output


def test_duplicate_ids_within_a_file(tmp_path: Path):
    body = _broken() + _broken().removeprefix("rules:\n")
    result = _run(str(_rules(tmp_path, body)))
    assert result.exit_code == 1
    assert "duplicate id in this file" in result.output


def test_rule_ids_cannot_inject_console_markup(tmp_path: Path):
    result = _run(str(_rules(tmp_path, _broken(id='"[bold red]x[/bold red]"'))))
    assert "[bold red]x[/bold red]" in result.output


@pytest.mark.parametrize("body", ["rules: [", "- just a list", "category: x\n", "rules: [1]\n"])
def test_unusable_files(tmp_path: Path, body: str):
    result = _run(str(_rules(tmp_path, body)))
    expected = 1 if body == "rules: [1]\n" else 2
    assert result.exit_code == expected, result.output


def test_needs_a_file_and_rejects_extra_args_elsewhere(tmp_path: Path):
    assert _run().exit_code == 2
    assert _run(str(tmp_path / "missing.yaml")).exit_code == 2
    assert CliRunner().invoke(main, [str(tmp_path), "extra.yaml"]).exit_code == 2


def test_several_files(tmp_path: Path):
    good = _rules(tmp_path, GOOD)
    bad = _rules(tmp_path, _broken(examples='{match: ["nope"]}'), "bad.yaml")
    result = _run(str(good), str(bad))
    assert result.exit_code == 1
    assert "1 rule(s) passed, 1 failed" in result.output
