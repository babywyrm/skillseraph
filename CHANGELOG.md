# Changelog

All notable changes to skillseraph are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Dockerfile** — multi-stage (python:3.12-slim + uv), GHCR push on main in CI.
  Enables the K8s init-container and admission webhook paths.
- **`--changed-only` / `--files-from`** — PR diff mode: scan only changed files
  (fast CI gate). The GHA action auto-diffs on pull_request events.
- **K8s init-container gate** — runnable Pod manifest + poisoned/clean ConfigMaps +
  `deploy/k8s/test-gate.sh` for end-to-end validation on any cluster.
- **K8s admission webhook** — ValidatingWebhookConfiguration + `webhook.py` that
  rejects ConfigMap creates/updates containing poisoned agent configs. Opt-in via
  namespace label `skillseraph.io/scan: "true"`.
- **Atlas J3 rules** (automation_triggers.yaml) — wildcard events, shell exec in
  automations, broad write permissions.
- **Atlas J5 rules** (config_inheritance.yaml) — parent traversal, absolute path
  includes, remote URL fetch, recursive globs.
- **`--generate-policy`** — emit a NullfieldPolicy YAML from findings, mapping
  critical/high→DENY, medium→HOLD, with a default-deny catch-all.
- **Action hardening** — `baseline` input, `changed-only` input (auto-diff),
  reusable workflow exposes all new inputs. Ready for `@v1` tag.
- 9 new tests (77 total).

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
