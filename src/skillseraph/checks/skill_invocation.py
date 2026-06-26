"""Atlas J2 — Skill invocation hijack checks (rules in rules/skill_invocation.yaml).

Threat class: SKILL.md and similar invocation-config files whose *invocation
semantics* are the attack surface — callback exfiltration, tool-call redirects,
self-modification, and override instructions that fire when the skill is called.
Distinct from J1 (rule injection): J1 is the file's text, J2 is what happens at
invocation time. References: OWASP MCP Top 10 (MCP03 Tool Poisoning, MCP06).
"""

from __future__ import annotations

from pathlib import Path

from ..models import Finding
from ..rules_engine import run_category


def check_skill_invocation(path: Path, content: str) -> list[Finding]:
    return run_category("skill_invocation", path, content)
