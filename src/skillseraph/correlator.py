"""Cross-file correlation — links related findings that span multiple files.

Detects attack patterns that are invisible when scanning file-by-file:
  - A rule/skill references another file that has findings
  - An automation triggers a hook that loads external content
  - A benign-looking config in one file enables a poisoned config in another
  - Multiple low-severity findings across files compose into a high-severity chain

Runs AFTER the per-file scan and augments the ScanResult with correlated findings.
"""

from __future__ import annotations

import re

from .models import Finding, Severity, ScanResult


# Cross-reference patterns: one file points at another.
_REFERENCE_PATTERNS = [
    re.compile(r"(?i)(?:extends|include|import|source|from|ref|path)\s*[:\s]*[\"']?([^\s\"']+\.(?:md|mdc|json|yaml|yml))", re.MULTILINE),
    re.compile(r"(?i)\"(?:skill|hook|rule|config|policy)\"\s*:\s*\"([^\"]+)\""),
    re.compile(r"(?i)(?:skillPath|hookPath|rulePath|configPath)\s*[:\s]*\"([^\"]+)\""),
]

# Chain amplification: when these finding categories appear together across files,
# the combined risk is higher than either alone.
_CHAIN_AMPLIFIERS: list[tuple[str, str, str, Severity]] = [
    # (category_A, category_B, chain_description, amplified_severity)
    ("injection", "persistence", "Injected instruction + persistence mechanism = persistent behavioral control", Severity.CRITICAL),
    ("injection", "suppression", "Injected instruction + review suppression = undetectable override", Severity.CRITICAL),
    ("exfiltration", "suppression", "Data exfil + review suppression = silent data theft", Severity.CRITICAL),
    ("authority_fabrication", "permission_bypass", "Fabricated authority + permission bypass = unauthorized privileged access", Severity.CRITICAL),
    ("tool_abuse", "runtime_bypass", "Tool abuse + runtime bypass = unrestricted execution", Severity.HIGH),
    ("mcp_servers", "injection", "Poisoned MCP server + injection = server-mediated agent hijack", Severity.CRITICAL),
]


def correlate(result: ScanResult) -> ScanResult:
    """Augment scan results with cross-file correlation findings."""
    if not result.findings:
        return result

    correlated: list[Finding] = []

    # Phase 1: reference-chain detection.
    correlated.extend(_find_reference_chains(result))

    # Phase 2: cross-file category amplification.
    correlated.extend(_find_chain_amplifiers(result))

    if correlated:
        result.findings = list(result.findings) + correlated

    return result


def _find_reference_chains(result: ScanResult) -> list[Finding]:
    """Find files that reference other files which have findings."""
    findings_by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        key = str(f.path.relative_to(result.target)) if result.target and f.path.is_relative_to(result.target) else str(f.path)
        findings_by_file.setdefault(key, []).append(f)

    chain_findings: list[Finding] = []
    # For each scanned file, check if it references other files that have findings.
    for scanned_file in result.target.rglob("*") if result.target else []:
        if not scanned_file.is_file() or scanned_file.suffix not in (".md", ".mdc", ".json", ".yaml", ".yml"):
            continue
        try:
            content = scanned_file.read_text(errors="replace")
        except OSError:
            continue

        for pattern in _REFERENCE_PATTERNS:
            for match in pattern.finditer(content):
                ref_path = match.group(1)
                # Check if the referenced path has findings.
                for file_key, file_findings in findings_by_file.items():
                    if ref_path in file_key or file_key.endswith(ref_path):
                        worst = max(file_findings, key=lambda f: f.severity.score)
                        chain_findings.append(Finding(
                            path=scanned_file,
                            check="cross_file_reference_chain",
                            severity=Severity.HIGH,
                            title=f"References file with findings: {ref_path}",
                            detail=(
                                f"This file references '{ref_path}' which has "
                                f"{len(file_findings)} finding(s) (worst: {worst.severity.value}). "
                                f"The reference creates a chain: content from the poisoned file "
                                f"may be loaded and executed through this reference."
                            ),
                            line=0,
                            evidence=match.group(0)[:100],
                            taxonomy_id="MCP-T05",
                            atlas_id="J5",
                        ))
                        break
    return chain_findings


def _find_chain_amplifiers(result: ScanResult) -> list[Finding]:
    """Detect when findings from different categories compose into a more severe chain."""
    # Group findings by category (check prefix before the first dot or underscore).
    categories_present: dict[str, list[Finding]] = {}
    for f in result.findings:
        # Match the finding's check ID against known category names.
        for known_cat in ("injection", "exfiltration", "permission_bypass", "encoding",
                          "urls", "suppression", "persistence", "tool_abuse",
                          "authority_fabrication", "runtime_bypass", "breakglass",
                          "mcp_servers", "automation_triggers", "config_inheritance"):
            if known_cat in f.check:
                categories_present.setdefault(known_cat, []).append(f)

    chain_findings: list[Finding] = []
    seen_chains: set[tuple[str, str]] = set()
    for cat_a, cat_b, description, severity in _CHAIN_AMPLIFIERS:
        if cat_a in categories_present and cat_b in categories_present:
            chain_key = (cat_a, cat_b)
            if chain_key in seen_chains:
                continue
            seen_chains.add(chain_key)

            exemplar_a = categories_present[cat_a][0]
            exemplar_b = categories_present[cat_b][0]
            chain_findings.append(Finding(
                path=exemplar_a.path,
                check="cross_file_chain_amplification",
                severity=severity,
                title=f"Attack chain: {cat_a} + {cat_b}",
                detail=(
                    f"{description}. "
                    f"Found '{cat_a}' in {exemplar_a.path.name} (line {exemplar_a.line}) "
                    f"and '{cat_b}' in {exemplar_b.path.name} (line {exemplar_b.line}). "
                    f"Together these compose into a more severe attack than either alone."
                ),
                line=exemplar_a.line,
                evidence=f"{exemplar_a.check} + {exemplar_b.check}",
                taxonomy_id="MCP-T05",
                atlas_id="J5",
            ))
    return chain_findings
