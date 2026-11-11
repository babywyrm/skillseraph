"""IDE config, task/debug, and APM integration checks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from ..models import Finding, Platform, Severity
from ..rules_engine import run_category

_APM_KEYS = {
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "DD_TRACE_AGENT_URL",
    "DD_AGENT_HOST",
    "SENTRY_DSN",
    "NEW_RELIC_HOST",
    "HONEYCOMB_API_HOST",
    "ELASTIC_APM_SERVER_URL",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
_USERINFO = re.compile(r"(https?://)[^/\s\"']+@")


def check_ide_integrations(path: Path, content: str) -> list[Finding]:
    findings = run_category("ide_integrations", path, content)
    for finding in findings:
        if finding.check == "ide_apm_external_collector":
            finding.evidence = _scrub_userinfo(finding.evidence)
            finding.detail = _scrub_userinfo(finding.detail)
    findings.extend(_check_extension_recommendations(path, content))
    seen = {finding.check for finding in findings}
    findings.extend(_check_apm_endpoints(path, content, seen))
    return findings


def _scrub_userinfo(text: str) -> str:
    return _USERINFO.sub(r"\1", text)


def _endpoint_host(value: str) -> str | None:
    if not value.lower().startswith(("http://", "https://")):
        return None
    host = urlparse(value).hostname
    if not host or host.lower() in _LOCAL_HOSTS:
        return None
    return host


def _check_apm_endpoints(path: Path, content: str, seen: set[str]) -> list[Finding]:
    """Pretty-printed settings put the endpoint on its own line, which the regex misses."""
    if "ide_apm_external_collector" in seen:
        return []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    found: str | None = None

    def walk(node: object) -> None:
        nonlocal found
        if found or not isinstance(node, dict):
            if isinstance(node, list):
                for item in node:
                    walk(item)
            return
        for key, value in node.items():
            if isinstance(key, str) and key.upper() in _APM_KEYS and isinstance(value, str):
                host = _endpoint_host(value)
                if host:
                    found = f"{key}={host}"
                    return
            walk(value)
            if found:
                return

    walk(data)
    if not found:
        return []
    return [Finding(
        path=path,
        check="ide_apm_external_collector",
        severity=Severity.MEDIUM,
        title="IDE or agent config points APM/telemetry to an external collector",
        detail="A JSON assignment routes traces, logs, or errors to a remote collector.",
        evidence=found,
        taxonomy_id="MCP-T12",
        atlas_id="J4",
    )]


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
