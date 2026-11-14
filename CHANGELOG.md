# Changelog

All notable changes to skillseraph are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); this project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- **Scanned trees are treated as hostile.**
  - A symlink inside a repo that resolves outside it is reported as
    `scan_symlink_outside_target` and never read, so a cloned repo cannot
    pull files from the scanning machine into a report (CWE-59).
    `audit-local` still follows symlinks, since dotfiles often are links.
  - Files are read up to 4 MiB; a larger agent config gets
    `agent_config_oversized` and only its first 4 MiB is checked (CWE-400).
  - Twelve patterns that backtracked polynomially on one long line (a scan
    could run for minutes) now match in linear time with identical results
    (CWE-1333). `rules-test` fails a pattern that is slow on long input, so
    a contributed rule cannot reintroduce this.
  - File paths and the scan target are escaped before reaching the console,
    so a crafted filename cannot inject terminal markup or links.
- **Reports no longer copy secret values (CWE-532).** Line rules stored the
  matched line as `evidence` and `detail`, so a one-line `"API_TOKEN":
  "<value>"`, an `Authorization: Bearer` header, or a token in a command
  reached console, JSON, SARIF, and webhook output. Every finding is now
  redacted before it leaves the scanner: credential-named key values,
  secret flag values (`--api-key VALUE`), auth-scheme values, common token
  shapes, and URL userinfo. `${VAR}`
  references stay. Findings whose evidence held a secret get a new
  fingerprint, so re-save baselines that covered them.
- **Admission webhook rejects unsafe data keys.** Keys were joined straight
  onto the scan directory, so a request posted directly to the webhook with a
  key such as `../name` wrote outside it (CWE-22). Keys that are not valid
  ConfigMap keys now deny the request and are never written.
- **Composite action no longer interpolates inputs into shell.** `path`,
  `fail-on`, `baseline`, and the other inputs reach the run step through
  environment variables, so a crafted input value cannot run commands
  (CWE-78).
- **Pinned CI supply chain.** Every third-party action is pinned to a commit
  SHA, the Docker base and `uv` images are pinned by digest, and Dependabot
  (with a 7-day cooldown) keeps them current. Workflows default to read-only
  tokens, checkouts drop persisted credentials, and the publish jobs each get
  only the permission they use. The release job uses `gh` instead of a
  third-party release action. CI runs `zizmor` on every workflow.

### Changed

- **Breaking: errors exit 2.** A bad option, missing target, unreadable or
  expired baseline, or internal error now exits `2` with a one-line message
  instead of `1` or a traceback, so CI can tell "findings" (`1`) from "no
  verdict" (`2`). Gates that fail on any non-zero code are unaffected.
- **README documents the JSON report and exit codes.** Every report field is
  listed, `tests/test_docs.py` fails if the list drifts from the output, and
  the standards section now names the ids findings carry (`MCP-T01`–`MCP-T14`
  and Atlas) instead of claiming an OWASP LLM mapping they do not emit.
- **Strict typing.** The package passes `mypy --strict`, and CI runs it on
  every Python and OS in the matrix. Rules loaded from YAML have a typed
  shape (`Rule`), and `write_policy` no longer takes unused keyword
  arguments.
- **Breaking: gates ignore bare suppressions.** With any `--fail-on` other
  than `none`, in `--watch`, and in the admission webhook, an ignore comment
  or `.skillseraphignore` line counts only with `reason`, `owner` (a role id),
  and an unexpired `until`. Add those fields, or the finding fails the gate.
- **`mcp_server_npx_remote_package` means git or URL sources.** It stays
  critical for `git+`, `http(s)://`, and `github:`/`gitlab:`/`bitbucket:`/
  `gist:` specs. Registry packages such as `npx -y @scope/pkg` no longer
  match it; the new `mcp_server_unpinned_package` (medium) flags them when
  they lack an exact version. Before, any `@` counted, so a scoped package
  was critical on one line and clean when pretty-printed.

### Fixed

- **Image and font assets are no longer scanned as text.** Skill folders
  ship PNGs and fonts, and their bytes produced noise findings. Files with
  image, font, archive, and library extensions are skipped; text files are
  still scanned even if they contain NUL bytes, so a stray NUL cannot hide
  a config.
- **`--baseline` dropped governed exceptions.** Applying a baseline rebuilt
  the result without its `exceptions`, so the JSON report and the console
  count lost the evidence for every honored exception. The baseline now
  removes only matched findings.
- **Correlation read files the scan never covered.** The reference-chain
  pass walked every `.md`/`.json`/`.yaml` under the target, so `audit-local`
  read the whole home directory and a repo scan read `node_modules`. It now
  reads only the scanned files. On a typical workstation `audit-local` went
  from minutes to about a second and stopped reporting chains through
  unrelated files.
- **Plain `mcp.json` servers skipped the server inspector.** Cursor,
  Windsurf, VS Code (`servers`), and Claude Desktop configs only got the
  line regexes, so argv-list commands, `trust`, and other structural checks
  missed them. They now get the same pass as Codex TOML and embedded
  servers.
- **Commented JSON was skipped.** The structural MCP, devcontainer
  lifecycle, and IDE checks used strict `json.loads`, so a JSONC file (with
  `//` comments or trailing commas, normal in VS Code and devcontainers) was
  only seen by the line rules and split commands went unflagged. They now
  share one JSONC-tolerant parser, and a non-object `extensions.json` no
  longer crashes the scan.
- **Docs match the tool.** QUICKSTART had PyPI installs, a `-v` flag that does
  not exist, `@v1` action refs (the release workflow creates `v0` for 0.x),
  and a Cursor hook in an unsupported format. QUICKSTART, `scan.yml`,
  `install.sh`, and the admission README are corrected, and QUICKSTART now
  covers `audit-local`. `tests/test_docs.py` fails if a documented flag,
  action ref, or Cursor hook example stops matching.
- **Directory patterns scan the same files on every Python.** On 3.11 and
  3.12 a trailing `**` (as in `.codex/**`) matched only the directory, so
  files such as `.codex/config.toml` were never scanned. Matched directories
  are now walked.
- **README and ROADMAP no longer claim PyPI or a container image.** The
  v0.2.0 PyPI upload failed at OIDC and the image job has never built.
  Install paths now list `install.sh`, a git install, and a local
  checkout; distribution is rated thin until both are repaired.

### Added

- **Hidden Unicode detection.** The old `invisible_unicode` rule only
  matched escaped `\u200b` text, so real invisible characters passed. A new
  `unicode` check reads the decoded text, including strings behind JSON
  `\u` escapes:
  - `hidden_unicode_smuggled_text` (critical): Unicode tag characters or
    variation-selector runs that encode a string no editor shows; the
    evidence holds the decoded, redacted text. Flag emoji are exempt.
  - `hidden_unicode_bidi_control` (high): bidi overrides and isolates
    (Trojan Source, CVE-2021-42574).
  - `hidden_unicode_invisible` (medium): zero-width characters and soft
    hyphens next to ASCII. Emoji joiners, Persian and Indic joiners, and a
    leading byte-order mark stay quiet.
  - `hidden_unicode_mixed_script` (medium, medium confidence): a word that
    mixes Latin letters with Cyrillic look-alikes, as in spoofed hosts.
- **`skillseraph rules-test FILE...`.** Checks contributed rule files
  without the repo's pytest setup: required fields, valid severity and
  confidence, a pattern that compiles, ids that are unique and do not
  collide with packaged rules, and `examples.match` / `examples.no_match`
  samples that behave. Exits 1 on any failing rule, 2 on an unreadable file.
  Rule examples now live in the rule YAML, every packaged rule has at
  least one `match` example, and `test_rule_coverage.py` runs each
  through the scanner and holds every packaged file to `rules-test`.
- **Change-only audits with `--since FILE`.** Compares a run against an
  earlier `--inventory` file and lists MCP servers, extensions, hooks, and
  files that were added, changed (with field names), or removed. Anything
  added or changed exits 1, so a new MCP server or extension stands out
  even when no rule fires. A malformed or unreadable snapshot exits 2, and
  names from it are printed as text, never as console markup.
- **A2A agent cards.** `.well-known/agent-card.json` and `agent.json` are
  scanned. `a2a_card_text_injection` (severity of the matched rule) decodes
  every card string and re-runs the injection rules, reporting only what JSON
  escapes hid from the line scan. `a2a_card_plaintext_endpoint` (high) flags
  `http://` endpoints, and `a2a_card_no_auth` (low) flags remote endpoints
  without `securitySchemes` or `security`. Evidence names fields and hosts.
- **`--inventory FILE`.** Writes a verdict-free JSON list of the MCP servers,
  extensions, hooks, and files a scan or `audit-local` read, for fleet
  audits. Commands are redacted, env entries are key names only, URLs are
  hosts only, paths are relative to the target, and absolute paths in
  commands are shown as `<target>/…` or `~/…`.
- **pre-commit hook.** `.pre-commit-hooks.yaml` ships `id: skillseraph`, so a
  repo can gate commits with `repo: https://github.com/babywyrm/skillseraph`
  and no local install. QUICKSTART's old `repo: local` example needed one and
  missed newer client files through its `files:` filter.
- **Literal secrets in MCP server configs.** `mcp_server_literal_secret`
  (high) flags credential-named or token-shaped `env` and `headers` values
  that are not `${VAR}`/`{env:VAR}` references or placeholders, in every
  format the server inspector reads. Evidence lists key names only.
- **Roo Code, Kiro, Amazon Q Developer, Aider, and Goose.** New platforms
  `roo`, `kiro`, `amazonq`, `aider`, and `goose` in repo scans and
  `audit-local`, using each client's documented paths. Their MCP servers go
  through the shared server inspector, including Amazon Q agent files and
  Goose `extensions` (YAML `cmd`/`uri`/`envs`). Kiro `autoApprove: ["*"]`
  counts as a wildcard tool list; Amazon Q `allowedTools` globs that cover
  `execute_bash` count as unscoped shell; Amazon Q agent hooks and Aider
  `test-cmd`/`lint-cmd`/`notifications-command` get the lifecycle check;
  Aider `yes-always: true` is an approval bypass.
- **MCP server version pinning.** `mcp_server_unpinned_package` (medium)
  flags `npx`, `bunx`, `pnpx`, `uvx`, `npm exec`, and `pnpm`/`yarn dlx`
  launches that are not pinned to an exact version (`pkg@1.2.3`,
  `pkg==1.2.3`), including `--package` and `--from` forms. Local paths and
  git or URL sources are left to the other checks.
- **Hooks in agent client settings.** Claude Code and Gemini CLI settings
  `hooks` and `statusLine`, Codex inline `[hooks]` and `notify`, and
  `~/.codex/hooks.json` now go through the lifecycle remote-exec check. MCP
  server commands in the same files stay with the MCP checks. New
  `agent_hook_remote_http` (high) flags HTTP hooks that post tool events to
  a non-local host; evidence is the host only.
- **Agent permission modes.** A parsed pass over Claude Code settings, Codex
  `config.toml` (including profiles), Gemini CLI settings, and Cursor CLI
  `cli.json` / `cli-config.json`. `agent_permission_bypass_mode` flags
  Claude `bypassPermissions` (high) and Codex `approval_policy = "never"`
  (medium); `agent_permission_sandbox_off` flags Codex `danger-full-access`;
  `agent_permission_wildcard_shell` flags shell allow rules with no command,
  a wildcard, or a shell interpreter. Repo scans now read `.cursor/cli.json`.
- **OTLP per-signal endpoints and inline header credentials.** The collector
  check covers `OTEL_EXPORTER_OTLP_{TRACES,METRICS,LOGS}_ENDPOINT`. New
  `ide_apm_inline_credential` (high) flags `OTEL_EXPORTER_OTLP*_HEADERS`
  that carry a literal auth header; env references are ignored and the
  report names the headers only.
- **Wildcard tools and TLS-off for Codex TOML and embedded servers.** The
  shared server inspector now flags `["*"]` tool lists (including
  `enabled_tools`) and disabled TLS verification, which the JSON-only
  regexes missed.
- **Gemini CLI, Zed, opencode, and more Copilot surfaces.** New platforms
  `gemini`, `zed`, and `opencode`. Repo scans read `GEMINI.md`, `.gemini/**`,
  `.zed/settings.json`, `.rules`, `opencode.json(c)`, `.opencode/**`, and
  Copilot's `.github/{instructions,prompts,chatmodes,agents}/**`,
  `.github/mcp.json`, and `.vscode/mcp.json`. `audit-local` reads
  `~/.gemini` (settings, commands, extension manifests), `~/.config/zed`,
  `~/.config/opencode`, `~/.copilot/mcp-config.json`, and the VS Code user
  `mcp.json` on macOS and Linux.
- **One structural pass for MCP servers embedded in client settings.** Claude
  `mcpServers`, Gemini `mcpServers`, Zed `context_servers`, opencode `mcp` /
  `mcp.servers` (argv-array `command`, `environment`), and Copilot CLI
  `mcpServers` all get the remote-URL, shell-command, remote-package, and
  credential-env checks.
- **`mcp_server_trust_bypasses_approval`** flags `trust: true`, which makes
  Gemini CLI run a server's tools without confirmation.
- **`SECURITY.md` and `CONTRIBUTING.md`.** Private vulnerability reporting,
  scope, the local checks CI runs, how to add a detection, and what a public
  contribution must not contain.
- **Action inputs `min-confidence` and `baseline-max-age`**, on both the
  composite action and the reusable workflow.
- **Rule contract test.** Every YAML rule id must be exercised by a test.
- **Linux container integration.** CI and `SKILLSERAPH_CONTAINER=1` run the
  image and scan both the macOS `Library` home layout and the Linux `.config`
  home layout inside it. The host suite still runs on Ubuntu and macOS.
- **Workstation agents on both layouts.** `audit-local` reads Claude Code
  (`~/.claude/settings.json`), Claude Desktop on macOS and Linux, and Continue
  config. Pretty-printed APM endpoints are detected, and endpoint evidence
  keeps the host and drops URL userinfo.
- **Codex and Cursor user-config audit.** `audit-local` reads
  `~/.codex/config.toml`, `~/.codex/rules`, `~/.codex/skills`, and Cursor's
  `~/.cursor/mcp.json`, `hooks.json`, `cli-config.json`, and `argv.json` on
  Linux and macOS.
- **APM collector assignments in JSON, YAML, and TOML.** The same external
  collector check now matches quoted JSON, YAML, and TOML. Localhost,
  `127.0.0.1`, and `0.0.0.0` stay unflagged.
- **Codex MCP servers in `config.toml`.** `[mcp_servers]` tables are checked
  for remote URLs, shell/fetch commands, and remote `npx`/`uvx` packages.
  Credential findings list env key names and omit values.
- **Governed exceptions.** When `--fail-on` is not `none`, and in the admission
  webhook, a suppression counts only with a reason, a role identifier, and an
  expiry. Bare ignores and path globs still apply to `--fail-on none`. Honored
  exceptions are included in the JSON report. `owner` is a role id; the field
  rejects an email address.
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

### Removed

- **The `sarif` extra.** It installed `sarif-om`, which nothing imports; SARIF
  output is written with the standard library.

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
