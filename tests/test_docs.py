"""Docs must describe commands, refs, and hook files that actually work."""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from pathlib import Path

from skillseraph.cli import main

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "QUICKSTART.md", ROOT / "deploy/k8s/admission/README.md"]
REF_FILES = DOCS + [ROOT / "action.yml", *sorted((ROOT / ".github/workflows").glob("*.yml"))]
_FENCE = re.compile(r"```(\w*)\n(.*?)```", re.DOTALL)
_REF = re.compile(r"babywyrm/skillseraph(?:/\.github/workflows/scan\.yml)?@([\w.-]+)")


def _cli_options() -> set[str]:
    options = {opt for param in main.params for opt in (*param.opts, *param.secondary_opts)}
    return options | {"--help"}


def _skillseraph_lines() -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for doc in DOCS:
        for _, block in _FENCE.findall(doc.read_text()):
            joined = block.replace("\\\n", " ")
            for line in joined.splitlines():
                command = line.split("#", 1)[0].strip()
                command = re.sub(r"^uvx\s+--from\s+\S+\s+", "", command)
                if re.match(r"^skillseraph(\s|$)", command):
                    lines.append((doc.name, command))
    for line in (ROOT / "install.sh").read_text().splitlines():
        match = re.search(r"printf '\s+(skillseraph[^#']*)", line)
        if match:
            lines.append(("install.sh", match.group(1).strip()))
    return lines


def test_documented_flags_exist() -> None:
    known = _cli_options()
    bad = [
        (source, token, command)
        for source, command in _skillseraph_lines()
        for token in shlex.split(command)
        if token.startswith("-") and token.split("=", 1)[0] not in known
    ]
    assert bad == []


def test_action_refs_match_published_major_tag() -> None:
    """publish.yml moves the major tag (v0 for 0.x) on each release; refs must use it."""
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    allowed = {f"v{version.split('.')[0]}", f"v{version}"}
    refs = {
        (path.name, ref)
        for path in REF_FILES
        for ref in _REF.findall(path.read_text())
        if ref not in allowed
    }
    assert refs == set()


def test_cursor_hook_examples_use_version_one_schema() -> None:
    for doc in DOCS:
        for lang, block in _FENCE.findall(doc.read_text()):
            if lang != "json" or '"hooks"' not in block:
                continue
            data = json.loads(block)
            assert data.get("version") == 1, doc.name
            assert isinstance(data.get("hooks"), dict), doc.name
