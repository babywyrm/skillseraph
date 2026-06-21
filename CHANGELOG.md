# Changelog

All notable changes to skillseraph are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet — see [ROADMAP.md](ROADMAP.md) for what's planned._

## [0.1.0] — 2026-06-20

Initial release. Multi-platform static scanner for agentic AI control-plane
config files.

### Added

- **Multi-platform scanning** across 11 platforms (Cursor, Codex, Copilot,
  Claude, Windsurf, Cline/Continue, Devin, Bedrock, LangChain, CrewAI, generic),
  with auto-detection and `--platform` override.
- **11 detection categories**: injection, exfiltration, permission bypass,
  encoding, URLs, suppression, persistence, tool abuse, authority fabrication,
  runtime bypass, break-glass.
- **Data-driven rules engine** — regex categories load from `rules/*.yaml`;
  adding a detection requires no code change.
- **Dependency-tree scanning** for configs planted in `node_modules/`,
  `vendor/`, `.venv/` (`--no-deps` to skip).
- **Baseline / allowlist** — `--save-baseline` accepts current findings;
  `--baseline` suppresses them on later runs (line-independent fingerprints).
- **CI gating** via `--fail-on {critical|high|medium|low|any|none}` (default `high`).
- **Output formats**: Rich console table, JSON (`--json-out`), SARIF 2.1.0
  (`--sarif`).
- **GitHub integration**: composite `action.yml` + reusable `scan.yml` workflow
  with SARIF upload to Code Scanning.
- **CI**: matrix tests on Linux + macOS, Python 3.11–3.13, with a dogfood self-scan.
- 68 unit/integration tests; standards mapping to OWASP LLM Top 10 and OWASP
  MCP Top 10; aligned to agentic-sec Attack Path Atlas Domain J.

[Unreleased]: https://github.com/babywyrm/skillseraph/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/babywyrm/skillseraph/releases/tag/v0.1.0
