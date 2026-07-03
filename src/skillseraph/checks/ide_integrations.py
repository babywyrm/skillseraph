"""IDE config, task/debug, and APM integration checks."""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Finding, Platform, Severity
from ..rules_engine import run_category


def check_ide_integrations(path: Path, content: str) -> list[Finding]:
    findings = run_category("ide_integrations", path, content)
    findings.extend(_check_extension_recommendations(path, content))
    return findings


def _check_extension_recommendations(path: Path, content: str) -> list[Finding]:
    if path.name != "extensions.json":
        return []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    recommendations = data.get("recommendations", [])
    if not isinstance(recommendations, list):
        return []

    findings: list[Finding] = []
    suspicious_markers = ("http://", "https://", ".vsix", "evil", "shadow", "unknown")
    for recommendation in recommendations:
        if not isinstance(recommendation, str):
            continue
        lowered = recommendation.lower()
        if any(marker in lowered for marker in suspicious_markers):
            findings.append(Finding(
                path=path,
                check="ide_untrusted_extension_recommendation",
                severity=Severity.MEDIUM,
                title="IDE config recommends an untrusted extension source",
                detail=(
                    "Workspace extension recommendations influence what developers install. "
                    "Verify URL-like, local package, or suspicious extension references before trust."
                ),
                evidence=recommendation[:200],
                platform=Platform.VSCODE,
                taxonomy_id="MCP-T08",
                atlas_id="D3",
            ))
    return findings
