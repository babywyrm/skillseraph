"""Baseline / allowlist support.

A baseline records the fingerprints of findings that have been reviewed and
accepted, so subsequent scans only surface *new* findings. Fingerprints are
line-independent (path + check + normalized evidence) so they survive code
movement within a file.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import Finding, ScanResult


def fingerprint(finding: Finding, root: Path) -> str:
    """Stable, line-independent fingerprint for a finding."""
    try:
        rel = finding.path.relative_to(root)
    except ValueError:
        rel = finding.path
    evidence = " ".join(finding.evidence.split()).lower()
    raw = f"{rel}|{finding.check}|{evidence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: Path) -> set[str]:
    """Load accepted fingerprints from a baseline file."""
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


def save_baseline(result: ScanResult, path: Path) -> int:
    """Write all current findings as an accepted baseline. Returns count."""
    fps = sorted({fingerprint(f, result.target) for f in result.findings})
    path.write_text(json.dumps({
        "version": 1,
        "target": str(result.target),
        "fingerprints": fps,
    }, indent=2))
    return len(fps)


def apply_baseline(result: ScanResult, baseline_fps: set[str]) -> ScanResult:
    """Return a new ScanResult with baseline-matched findings removed."""
    kept = [
        f for f in result.findings
        if fingerprint(f, result.target) not in baseline_fps
    ]
    return ScanResult(
        target=result.target,
        findings=kept,
        files_scanned=result.files_scanned,
        platforms_detected=result.platforms_detected,
    )
