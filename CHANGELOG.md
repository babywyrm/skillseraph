# Changelog

All notable changes to skillseraph are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- **README and ROADMAP no longer claim PyPI or a container image.** The
  v0.2.0 PyPI upload failed at OIDC and the image job has never built.
  Install paths now list `install.sh`, a git install, and a local
  checkout; distribution is rated thin until both are repaired.

### Added

- **Supply-chain trust detection (`supply_chain_trust`)** — flags skill/plugin/
  tool sources that auto-deploy or skip human review, remote sources marked
  `trusted`/`verified` (unearned scrutiny reduction), and remote skill feeds/
  registries (Atlas D3/J5).
- **Runtime escape-surface detection (`runtime_escape`)** — flags container
  runtime sockets (`docker.sock`, `containerd.sock`, `crio.sock`), kubelet API
  references, service-account token paths, and host-namespace/privileged
  markers (Atlas J4).
- **Approver-manipulation detection (`approver_manipulation`)** — flags indirect
  prompt injection aimed at an automated reviewer/LLM-judge (mark-as-safe,
  forced ALLOW verdicts, "you are the security filter") (OWASP LLM01, Atlas J2/I3).
- **Monitoring blind-spot detection (`monitoring_bypass`)** — flags configs that
  disable audit/logging, add wildcard security exceptions, or disable detection
  rules (Atlas J3).
- **Baseline expiry** — `save_baseline` now records a creation timestamp and
  `--baseline-max-age <days>` fails the run when the baseline is older than the
  limit (or predates timestamping), so accepted findings can't be suppressed
  indefinitely without re-review.
- **Rule confidence tuning pass** — every rule pack now carries calibrated
  `confidence` values: deterministic/structural patterns stay `high`, natural-
  language instruction heuristics are `medium`, and broad blob/role-marker
  patterns (base64/hex blobs, bare `system:`/`assistant:` markers) are `low`,
  so `--min-confidence high` yields a high-signal gate.
- **SARIF confidence mapping** — SARIF results now include a `rank`
  (severity × confidence, 0–100) and `confidence`/`security-severity`
  properties so GitHub Code Scanning can sort and filter by confidence.
- **JetBrains IDE coverage** — new `jetbrains` platform scans `.idea/**/*.xml`
  (run configurations, external tools) and `*.iml` files, with a `jetbrains`
  rule pack flagging run configs / external tools that fetch remote content or
  inject secret-bearing environment variables.
- **Extension publisher allowlist** — `audit-local --allow-extension-publisher
  <name>` (repeatable) flags any installed extension whose publisher is not on
  the trusted list as an informational, low-confidence finding, surfacing
  typosquatted or side-loaded extensions even with a clean manifest.
- **Structural lifecycle/hook parsing** — `devcontainer.json` and `hooks.json`
  get a JSON-aware pass (`lifecycle` check) that reassembles array/object-form
  commands before matching, catching remote-fetch-to-interpreter payloads that
  are split across lines and invisible to the line-regex engine.
- **Structural MCP config parsing** — `mcp.json`-family files now also get a
  JSON-aware pass that catches multi-line field tampering the line-regex
  engine cannot see (env credential blocks and wildcard tool allowlists
  formatted one key per line), deduplicated against regex findings.
- **Installed-extension auditing** — `audit-local` now inspects extension
  manifests under `.vscode/extensions`, `.cursor/extensions`, and
  `.windsurf/extensions` via a structural JSON parser (`extensions` check):
  wildcard activation, lifecycle scripts fetching remote code, and entry
  points escaping the install directory.
- **Per-rule confidence scores** — rules may declare `confidence:
  high|medium|low`; findings carry it in console/JSON output and
  `--min-confidence` filters heuristic matches on large repos.
- **Inline ignores + `.skillseraphignore`** — suppress a named rule on one
  line with `skillseraph: ignore <rule>` comments, exclude paths with globs,
  or disable a rule repo-wide with `rule:<id>` lines.
- **Safe demo and smoke-test flows** — `skillseraph demo-fixture --output <dir>`
  writes synthetic repo/home fixtures with fake poisoned configs, and
  `skillseraph smoke-test` verifies expected detections in a temporary fixture.
- **VS Code-compatible IDE self-checks** — new `vscode` platform coverage for
  `.vscode/{settings,tasks,launch,extensions}.json`, `*.code-workspace`, and
  `.devcontainer/**`, plus `skillseraph audit-local` for user-level VS Code,
  Cursor, and Windsurf config audits.
- **`ide_integrations` rule pack** — detects remote shell pipes in IDE tasks,
  secret env injection, runtime preload hooks, suspicious extension trust
  signals, and APM/telemetry collector redirects.
- **`skill_invocation` rule pack (Atlas J2)** — detects skill invocation hijack
  distinct from rule injection: callback/webhook on invocation, tool-call
  redirects, skill self-modification, invocation-time overrides, load-time
  exfil, silent invocation, and remote skill pull. Wired via a new
  `check_skill_invocation` module.
- **Sleeper / conditional-trigger detection (Atlas C1)** in the `injection`
  pack — if-then triggers, keyword/passphrase-activated modes, selective
  disclosure, and time/turn-based delayed activation.
- **Tool schema smuggling (Atlas I3)** in `mcp_servers` — instruction override,
  exfil URLs, and role-marker injection hidden in MCP tool `description`/
  parameter fields.
- **Supply-chain patterns (Atlas D1/D3/D4)** in `tool_abuse` — unpinned agent
  package installs, `package.json` lifecycle hooks referencing agent tooling,
  CI secret exposure, and non-canonical registry redirects.
- **Encoding pack extended** — `eval(atob())` decode-then-execute, ROT13/`tr`
  pipes, and `String.fromCharCode`/hex-escape concatenation, in addition to the
  existing base64/hex/unicode/data-URI checks.
- 27 new tests (`test_extended_coverage.py`) + `poisoned_skill_invocation.md`
  fixture.

### Changed

- **Detection noise reduced** — tightened jailbreak, dangerous tool invocation,
  and outbound data push rules to avoid matching benign prose, markdown code
  fences, and protocol documentation while preserving command-shaped abuse.
- **`encoding` is now fully data-driven** — `encoding.py` delegates to
  `rules/encoding.yaml` via the rules engine, removing the duplicate hardcoded
  regexes so there is a single source of truth (and no double-reporting).
- `__version__` bumped to `0.2.0` to match `pyproject.toml` (banner now shows
  the correct version).

### Fixed

- **False positives from a benign-config QA sweep** — `sandbox_bypass` no longer
  flags `auto_approve` config keys (only the instruction form);
  `broad_monitoring_exception` no longer flags VS Code `files.exclude`/generic
  exclude globs; and `mcp_server_stdio_arbitrary_command` no longer flags normal
  stdio launchers (`node`/`npx`/`uvx`/`python`).
- **Dead rule patterns** — `j3_broad_write_permissions` used an unmatchable
  multiline regex and `mcp_server_raw_ip` only matched an IP at the very end of
  a URL; both now fire correctly. Added `tests/test_rule_coverage.py` as a guard
  that every rule fires on a crafted positive sample.
- **MCP rule scoping** — MCP server rules now run only on MCP config files, so
  VS Code task/debug configs no longer receive MCP-specific findings.
- **Watch mode `NameError`** — `cli.py` referenced `platforms` before it was
  defined; the assignment now precedes the `--watch` branch.
- Lint: removed unused `Path` import and dead `cat` local in `correlator.py`;
  renamed ambiguous `l` loop vars in `cli.py`.

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
