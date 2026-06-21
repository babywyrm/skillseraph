"""Core data models for skillseraph findings and configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        return {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}[self.value]


class Platform(str, Enum):
    CURSOR = "cursor"
    CODEX = "codex"
    COPILOT = "copilot"
    CLAUDE = "claude"
    WINDSURF = "windsurf"
    CLINE = "cline"
    DEVIN = "devin"
    BEDROCK = "bedrock"
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    GENERIC = "generic"


@dataclass
class PlatformSpec:
    """Defines where a platform stores agent config and what to look for."""

    name: Platform
    file_patterns: list[str]
    description: str
    dep_plant_paths: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """A single security finding from a scan."""

    path: Path
    check: str
    severity: Severity
    title: str
    detail: str
    line: int | None = None
    evidence: str = ""
    platform: Platform = Platform.GENERIC
    taxonomy_id: str = ""
    atlas_id: str = ""
    mitre_id: str = ""

    @property
    def location(self) -> str:
        if self.line:
            return f"{self.path}:{self.line}"
        return str(self.path)


@dataclass
class ScanResult:
    """Aggregate result of a full scan."""

    target: Path
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    platforms_detected: list[Platform] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return min(self.findings, key=lambda f: f.severity.score).severity

    @property
    def risk_score(self) -> int:
        return sum(f.severity.score for f in self.findings)
