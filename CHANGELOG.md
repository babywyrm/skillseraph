# Changelog

All notable changes to skillseraph are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing pending._

## [0.2.0] — 2026-06-25

### Added

- **`install.sh`** — one-liner macOS/Linux installer. Detects and installs `uv`
  if missing (via the official Astral installer), then runs `uv tool install`
  to put `skillseraph` on PATH. Supports `SKILLSERAPH_REF` env var to pin a
  release (`SKILLSERAPH_REF=v0.1.0 curl … | sh`).
- **`publish.yml` GHA workflow** — automated PyPI publish on version-tag push
  via OIDC trusted publishing (no secret needed). Builds sdist + wheel with
  `uv build`, publishes via `pypa/gh-action-pypi-publish`, creates a GitHub
  Release with auto-generated notes, and updates the floating `v1` major tag
  so `uses: babywyrm/skillseraph@v1` always resolves.
- **PyPI distribution** — `skillseraph` is now `pip install skillseraph` /
  `uv tool install skillseraph` / `uvx skillseraph`.
- **GitHub Marketplace** — `action.yml` branding already present; floating
  `v1` tag wired up via `publish.yml`.

### Changed

- README `## Install` section rewritten: one-liner first, then PyPI, then uvx,
  then from-source (development). Removed the "Not yet published to PyPI" note.
- QUICKSTART rewritten: one-liner and PyPI paths added as primary options;
  GHA section now shows Marketplace `@v1` usage as Option A.

---

## [0.1.0] — 2026-06-20

Initial release. Multi-platform static scanner for agentic AI control-plane
config files.

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
- **Multi-platform scanning** across 11 platforms (Cursor, Codex, Copilot,
  Claude, Windsurf, Cline/Continue, Devin, Bedrock, LangChain, CrewAI, generic),
  with auto-detection and `--platform` override.
- **11 detection categories**: injection, exfiltration, permission bypass,
  encoding, URLs, suppression, persistence, tool abuse, authority fabrication,
  runtime bypass, break-glass.
- **Data-driven rules engine** — regex categories load from `rules/*.yaml`.
- **Dependency-tree scanning** for configs planted in `node_modules/`,
  `vendor/`, `.venv/` (`--no-deps` to skip).
- **Baseline / allowlist** — `--save-baseline` / `--baseline`.
- **CI gating** via `--fail-on`.
- **Output formats**: Rich console, JSON, SARIF 2.1.0.
- **GitHub integration**: composite `action.yml` + reusable `scan.yml` workflow.
- **CI**: matrix tests on Linux + macOS, Python 3.11–3.13, dogfood self-scan.
- 83 unit/integration tests; OWASP LLM / OWASP MCP / Attack Path Atlas Domain J.

[Unreleased]: https://github.com/babywyrm/skillseraph/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/babywyrm/skillseraph/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/babywyrm/skillseraph/releases/tag/v0.1.0
