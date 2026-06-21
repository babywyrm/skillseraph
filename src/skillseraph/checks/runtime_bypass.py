"""Detect command-blocklist bypass via language runtimes / interpreters.

Threat class: agent guardrails and tool sandboxes often blocklist obvious
binaries (cat, curl, bash). A common bypass is to invoke an allowed language
runtime to perform the same action — e.g. using a scripting interpreter's
file I/O or process APIs instead of the blocked binary. Configs that instruct
an agent to prefer these one-liners are a strong signal of intentional
blocklist evasion.

References: GTFOBins (living-off-the-land binaries), OWASP MCP Top 10
(MCP05 Command Injection).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import Finding, Severity

# Interpreter inline-execution flags wired to file/process/network access.
_PATTERNS: list[tuple[re.Pattern, str, Severity, str]] = [
    (
        re.compile(r"\bnode\s+-e\b.*(readFileSync|writeFileSync|child_process|require\s*\(|process\.)", re.IGNORECASE),
        "node_inline_bypass",
        Severity.HIGH,
        "Node.js inline execution wired to file/process APIs (blocklist bypass)",
    ),
    (
        re.compile(r"\bpython3?\s+-c\b.*(open\s*\(|os\.|subprocess|socket|requests)", re.IGNORECASE),
        "python_inline_bypass",
        Severity.HIGH,
        "Python inline execution wired to file/OS/network APIs (blocklist bypass)",
    ),
    (
        re.compile(r"\b(perl|ruby)\s+-e\b.*(open|system|exec|`|IO::)", re.IGNORECASE),
        "scripting_inline_bypass",
        Severity.HIGH,
        "Perl/Ruby inline execution wired to file/process APIs (blocklist bypass)",
    ),
    (
        re.compile(r"\bphp\s+-r\b.*(file_get_contents|fopen|system|exec|shell_exec)", re.IGNORECASE),
        "php_inline_bypass",
        Severity.HIGH,
        "PHP inline execution wired to file/process APIs (blocklist bypass)",
    ),
    (
        re.compile(r"(use|prefer|instead\s+use|fall\s?back\s+to)\s+.*(runtime|interpreter|node\s+-e|python\s+-c).*(blocked|blocklist|forbidden|denied|restricted)", re.IGNORECASE),
        "explicit_bypass_instruction",
        Severity.CRITICAL,
        "Explicit instruction to use a runtime to bypass a command blocklist",
    ),
    (
        re.compile(r"(echo|printf)\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+-d\s*\|\s*(sh|bash|python|node)", re.IGNORECASE),
        "encoded_pipe_to_shell",
        Severity.CRITICAL,
        "Base64-decoded payload piped to an interpreter (obfuscated execution)",
    ),
    (
        re.compile(r"\b(env|/usr/bin/env)\s+\w+\s+-(e|c)\b", re.IGNORECASE),
        "env_wrapped_interpreter",
        Severity.MEDIUM,
        "Interpreter invoked via env wrapper (may evade name-based blocklists)",
    ),
]


def check_runtime_bypass(path: Path, content: str) -> list[Finding]:
    """Scan for command-blocklist bypass via language runtimes."""
    findings: list[Finding] = []
    for line_num, line in enumerate(content.splitlines(), 1):
        for pattern, check_name, severity, title in _PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    path=path,
                    check=check_name,
                    severity=severity,
                    title=title,
                    detail=f"Line {line_num}: {line.strip()[:120]}",
                    line=line_num,
                    evidence=line.strip()[:200],
                    taxonomy_id="MCP-T05",
                    atlas_id="J4",
                ))
    return findings
