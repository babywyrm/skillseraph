"""A2A agent card checks (``.well-known/agent-card.json``, older ``agent.json``).

A client agent reads the card's names, descriptions, and skill examples into
its context, so card text is an indirect injection surface like an MCP tool
schema. JSON escapes (``\\u0069gnore``) hide that text from line rules, so
this pass decodes every string and re-runs the injection rules, reporting
only what the raw file hid. Endpoints get a plaintext and a no-auth check.
Evidence names fields and hosts, never values.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from ..models import Finding, Platform, Severity
from ..rules_engine import run_category
from . import load_jsonc

_CARD_NAMES = {"agent-card.json", "agent.json"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}


def _strings(node: object, where: str) -> list[tuple[str, str]]:
    if isinstance(node, str):
        return [(where, node)]
    if isinstance(node, dict):
        return [hit for k, v in node.items() for hit in _strings(v, f"{where}.{k}" if where else str(k))]
    if isinstance(node, list):
        return [hit for i, v in enumerate(node) for hit in _strings(v, f"{where}[{i}]")]
    return []


def _endpoints(card: dict[str, object]) -> list[tuple[str, str]]:
    found = [("url", card.get("url"))]
    interfaces = card.get("additionalInterfaces")
    if isinstance(interfaces, list):
        found += [
            (f"additionalInterfaces[{i}].url", item.get("url"))
            for i, item in enumerate(interfaces)
            if isinstance(item, dict)
        ]
    return [(field, url) for field, url in found if isinstance(url, str)]


def _finding(path: Path, check: str, severity: Severity, title: str, detail: str,
             evidence: str, taxonomy_id: str, atlas_id: str, confidence: str = "high") -> Finding:
    return Finding(
        path=path, check=check, severity=severity, title=title, detail=detail,
        evidence=evidence[:200], platform=Platform.A2A, taxonomy_id=taxonomy_id,
        atlas_id=atlas_id, confidence=confidence,
    )


def check_a2a_card(path: Path, content: str) -> list[Finding]:
    if path.name not in _CARD_NAMES or path.parent.name != ".well-known":
        return []
    card = load_jsonc(content)
    if not isinstance(card, dict):
        return []
    findings: list[Finding] = []

    visible = {f.check for f in run_category("injection", path, content)}
    hidden = [
        (field, hit)
        for field, text in _strings(card, "")
        for hit in run_category("injection", path, text)
        if hit.check not in visible
    ]
    if hidden:
        findings.append(_finding(
            path, "a2a_card_text_injection",
            max((hit.severity for _, hit in hidden), key=lambda s: s.score),
            "A2A agent card hides prompt injection in escaped text",
            "Card text that client agents load into context decodes to injection "
            "language the raw file does not show, which points to deliberate evasion.",
            ", ".join(f"{field}: {hit.check}" for field, hit in hidden[:3]),
            "MCP-T02", "I3",
        ))

    remote = [
        (field, host, url)
        for field, url in _endpoints(card)
        if (host := urlparse(url).hostname or "") and host not in _LOCAL_HOSTS
    ]
    plaintext = [(field, host) for field, host, url in remote if url.lower().startswith("http://")]
    if plaintext:
        findings.append(_finding(
            path, "a2a_card_plaintext_endpoint", Severity.HIGH,
            "A2A agent card advertises a plaintext endpoint",
            "Tasks, results, and any bearer credentials sent to this endpoint cross "
            "the network unencrypted.",
            ", ".join(f"{field}={host}" for field, host in plaintext[:3]),
            "MCP-T06", "J4",
        ))
    if remote and not card.get("securitySchemes") and not card.get("security"):
        findings.append(_finding(
            path, "a2a_card_no_auth", Severity.LOW,
            "A2A agent card declares no authentication",
            "The card lists a remote endpoint without securitySchemes or security, so "
            "clients will call it unauthenticated. Fine for a public agent; otherwise "
            "anyone who finds the card can send it tasks.",
            "no securitySchemes or security",
            "MCP-T03", "J4", confidence="medium",
        ))
    return findings
