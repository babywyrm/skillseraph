"""IDE config, task/debug, and APM integration checks."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from ..models import Finding, Platform, Severity
from ..rules_engine import run_category
from . import load_jsonc

_APM_KEYS = {
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
    "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    "DD_TRACE_AGENT_URL",
    "DD_AGENT_HOST",
    "SENTRY_DSN",
    "NEW_RELIC_HOST",
    "HONEYCOMB_API_HOST",
    "ELASTIC_APM_SERVER_URL",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
_USERINFO = re.compile(r"(https?://)[^/\s\"']+@")
_OTLP_HEADERS_KEY = re.compile(r"OTEL_EXPORTER_OTLP(?:_(?:TRACES|METRICS|LOGS))?_HEADERS", re.IGNORECASE)
_OTLP_HEADERS_LINE = re.compile(
    rf"[\"']?({_OTLP_HEADERS_KEY.pattern})[\"']?\s*[:=]\s*[\"']([^\"'\n]*)", re.IGNORECASE
)
_CREDENTIAL_HEADER = re.compile(
    r"(authorization|api[-_]?key|token|secret|x-honeycomb-team|dd-api-key)", re.IGNORECASE
)
_ENV_REFERENCE = re.compile(r"\$\{?[\w:]+\}?|\{env:\w+\}")


def check_ide_integrations(path: Path, content: str) -> list[Finding]:
    findings = run_category("ide_integrations", path, content)
    for finding in findings:
        if finding.check == "ide_apm_external_collector":
            finding.evidence = _scrub_userinfo(finding.evidence)
            finding.detail = _scrub_userinfo(finding.detail)
    findings.extend(_check_extension_recommendations(path, content))
    seen = {finding.check for finding in findings}
    findings.extend(_check_apm_endpoints(path, content, seen))
    findings.extend(_check_otlp_headers(path, content))
    return findings


def _inline_credential_headers(value: str) -> list[str]:
    """Header names in an OTLP ``k=v,k2=v2`` string whose value is a literal secret."""
    names = []
    for pair in value.split(","):
        name, sep, secret = pair.partition("=")
        secret = secret.strip()
        if sep and secret and _CREDENTIAL_HEADER.search(name) and not _ENV_REFERENCE.fullmatch(secret):
            names.append(name.strip())
    return names


def _check_otlp_headers(path: Path, content: str) -> list[Finding]:
    """Evidence names the headers only; the value is the secret."""
    hits: list[tuple[str, list[str]]] = []
    for match in _OTLP_HEADERS_LINE.finditer(content):
        hits.append((match.group(1), _inline_credential_headers(match.group(2))))

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and _OTLP_HEADERS_KEY.fullmatch(key) and isinstance(value, str):
                    hits.append((key, _inline_credential_headers(value)))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    if path.suffix in {".json", ".jsonc"}:
        walk(load_jsonc(content))
    for key, names in hits:
        if names:
            return [Finding(
                path=path,
                check="ide_apm_inline_credential",
                severity=Severity.HIGH,
                title="OTLP exporter headers hold an inline credential",
                detail="A collector credential is written into config instead of read from the environment.",
                evidence=f"{key}: {', '.join(names[:5])}",
                taxonomy_id="MCP-T07",
                atlas_id="J4",
            )]
    return []


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
    data = load_jsonc(content)
    if data is None:
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

    data = load_jsonc(content)
    if not isinstance(data, dict):
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
