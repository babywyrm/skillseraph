"""Hidden Unicode: text a reviewer cannot see but a model still reads.

Tag characters (U+E0000 block) and runs of variation selectors encode whole
strings invisibly; bidi controls reorder what a reviewer sees (Trojan Source,
CVE-2021-42574); zero-width characters split words past keyword rules; and a
Cyrillic letter inside a Latin word spoofs names and hosts. JSON ``\\u``
escapes are decoded and checked too, reporting only what the raw text hid.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from ..models import Finding, Severity
from . import load_jsonc, redact

_TAGS = re.compile("[\U000e0000-\U000e007f]+")
_SELECTOR_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_INVISIBLE = re.compile("[\u00ad\u180e\u200b-\u200d\u2060-\u2064\ufeff]")
_NON_ASCII_WORD = re.compile(r"\b\w*[^\W\x00-\x7f]\w*")
_BLACK_FLAG = "\U0001f3f4"
# Cyrillic letters drawn like Latin ones; others (zh, ya, ...) do not spoof.
_LATIN_LOOKALIKES = frozenset(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0455\u0456\u0458\u04bb\u04cf\u0501\u051b\u051d"
    "\u0405\u0406\u0408\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0425\u04ba\u051a\u051c"
)

_Hit = tuple[int, str]


def _codes(text: str) -> str:
    return " ".join(sorted({f"U+{ord(c):04X}" for c in text}))


def _smuggled(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for m in _TAGS.finditer(text):
        if m.start() and text[m.start() - 1] == _BLACK_FLAG:
            continue  # subdivision flag emoji, e.g. England
        decoded = "".join(chr(ord(c) - 0xE0000) for c in m.group() if 0xE0020 <= ord(c) <= 0xE007E)
        hits.append((m.start(), f"{len(m.group())} tag characters decode to {redact(decoded)[:80]!r}"))
    hits += [(m.start(), f"{len(m.group())} variation selectors in a row") for m in _SELECTOR_RUN.finditer(text)]
    return hits


def _bidi(text: str) -> list[_Hit]:
    return [(m.start(), _codes(m.group())) for m in _BIDI.finditer(text)]


def _invisible(text: str) -> list[_Hit]:
    # ponytail: "next to ASCII" separates hiding from emoji ZWJ sequences,
    # Persian/Indic ZWNJ, and CJK breaks; ASCII-adjacent legit use (rare in
    # agent config) still fires. Upgrade: per-script context rules.
    hits: list[_Hit] = []
    for m in _INVISIBLE.finditer(text):
        i = m.start()
        if i == 0 and m.group() == "\ufeff":
            continue
        neighbors = text[i - 1 : i] + text[i + 1 : i + 2]
        if any(" " <= c <= "~" for c in neighbors):
            hits.append((i, _codes(m.group())))
    return hits


def _mixed_script(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    for m in _NON_ASCII_WORD.finditer(text):
        word = m.group()
        if len(word) < 3:
            continue
        cyrillic = [c for c in word if c in _LATIN_LOOKALIKES]
        if cyrillic and any("a" <= c.lower() <= "z" for c in word):
            hits.append((m.start(), f"{word[:40]!r} has {_codes(''.join(cyrillic))}"))
    return hits


_CHECKS: list[tuple[str, Severity, str, str, str, Callable[[str], list[_Hit]]]] = [
    (
        "hidden_unicode_smuggled_text", Severity.CRITICAL, "high",
        "Invisible characters encode hidden text",
        ("Unicode tag characters or variation-selector runs carry a string no editor "
         "shows. Models read it, so it can hold instructions a reviewer never sees."),
        _smuggled,
    ),
    (
        "hidden_unicode_bidi_control", Severity.HIGH, "high",
        "Bidirectional control character reorders text",
        ("Bidi overrides and isolates make the displayed text differ from the stored "
         "text (Trojan Source, CVE-2021-42574), so review approves something else."),
        _bidi,
    ),
    (
        "hidden_unicode_invisible", Severity.MEDIUM, "high",
        "Invisible character inside ASCII text",
        ("Zero-width and soft-hyphen characters split words so keyword rules and "
         "reviewers miss them while a model still reads the joined text."),
        _invisible,
    ),
    (
        "hidden_unicode_mixed_script", Severity.MEDIUM, "medium",
        "Word mixes Latin and Cyrillic letters",
        ("A Cyrillic letter that looks Latin inside a word or host name spoofs a "
         "trusted name, a common homoglyph trick in URLs and package names."),
        _mixed_script,
    ),
]


def _json_text(path: Path, content: str) -> str:
    if "\\u" not in content or path.suffix not in {".json", ".jsonc"}:
        return ""
    strings: list[str] = []
    stack: list[object] = [load_jsonc(content)]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            strings.append(node)
        elif isinstance(node, dict):
            stack += [*node.keys(), *node.values()]
        elif isinstance(node, list):
            stack += node
    return "\n".join(strings)


def check_hidden_unicode(path: Path, content: str) -> list[Finding]:
    findings: list[Finding] = []
    decoded = _json_text(path, content)
    for check, severity, confidence, title, detail, find in _CHECKS:
        hits, where = find(content), detail
        line: int | None = None
        if hits:
            line = content.count("\n", 0, hits[0][0]) + 1
        elif decoded and (hits := find(decoded)):
            where = f"{detail} Found after decoding JSON \\u escapes, which hide it in the raw file."
        if hits:
            findings.append(Finding(
                path=path, check=check, severity=severity, title=title, detail=where, line=line,
                evidence="; ".join(h for _, h in hits[:3])[:200], taxonomy_id="MCP-T01", atlas_id="J1",
                confidence=confidence,
            ))
    return findings
