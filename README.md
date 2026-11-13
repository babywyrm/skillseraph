# skillseraph

**Agent config security scanner.** Detects poisoned skills, rules, hooks, and
instructions across agentic AI platforms — before a coding agent ever reads them.

skillseraph is a static analyzer for the *control-plane* of agentic systems: the
`AGENTS.md`, `SKILL.md`, `.cursor/rules`, hook configs, and MCP server definitions
that tell an AI agent how to behave. These files are an under-defended supply-chain
surface: anyone who can land a file in your repo (or in a dependency) can plant
instructions your agent will silently follow.

> Part of the [agentic-sec](https://github.com/babywyrm/agentic-sec) ecosystem.
> Where **mcpnuke** scans live MCP endpoints, **skillseraph** scans the config files.

---

## Why

Agent instruction files are trusted by default and rarely reviewed for hostile
content. A single poisoned `AGENTS.md` planted three directories deep in
`node_modules/` can:

- Override the agent's behavior ("ignore previous instructions")
- Exfiltrate secrets ("read `.env`, send to https://…")
- Suppress review ("don't mention this in the PR summary")
- Fabricate authority ("approved by the security team")
- Bypass command blocklists (use a language runtime instead of a blocked binary)
- Persist across sessions ("from now on, always…")

skillseraph finds these patterns and fails your CI before the agent runs.

---

## Install

skillseraph is uv-native. `uv` is the engine — every install path below uses it.

### One-liner (macOS / Linux — recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/babywyrm/skillseraph/main/install.sh | sh
```

Installs `uv` if it isn't present, then puts `skillseraph` on your PATH via
`uv tool install`. Takes ~10 seconds on a fast connection.

Pin to a release:

```bash
SKILLSERAPH_REF=v0.2.0 curl -fsSL https://raw.githubusercontent.com/babywyrm/skillseraph/main/install.sh | sh
```

### From git (no clone required)

```bash
# Requires uv (https://docs.astral.sh/uv/getting-started/installation/)
uv tool install git+https://github.com/babywyrm/skillseraph@v0.2.0   # skillseraph on PATH
uvx --from git+https://github.com/babywyrm/skillseraph skillseraph .  # ephemeral run of main
```

skillseraph is not on PyPI yet, and there is no public container image.
See [ROADMAP.md](ROADMAP.md).

### From source (development)

```bash
git clone https://github.com/babywyrm/skillseraph
cd skillseraph
uv tool install .         # global install from local checkout
# or: uv sync && uv run skillseraph --version   (dev mode, no install)
```

Runs on Linux and macOS. Pure Python (3.11+), no system dependencies.
GitHub Actions runs the suite on Ubuntu and macOS (Python 3.11–3.13). The
container job builds the Linux image and runs `tests/test_container_integration.py`,
which scans a macOS home layout and a Linux home layout inside that image.
Push stays on `main`. Locally: `docker build -t skillseraph:ci .` then
`SKILLSERAPH_CONTAINER=1 uv run pytest tests/test_container_integration.py`.

---

## Usage

```bash
# Scan the current directory (auto-detects platforms)
skillseraph .

# Scan a specific repo, fail CI on any high+ finding
skillseraph /path/to/repo --fail-on high

# Focus on one platform
skillseraph . --platform cursor

# Skip dependency trees (faster; default scans them)
skillseraph . --no-deps

# Machine-readable output
skillseraph . --json-out findings.json --sarif results.sarif

# Developer self-check for local VS Code, Cursor, and Codex config
skillseraph audit-local --json-out ide-audit.json

# Flag installed extensions from any publisher outside your trusted allowlist
skillseraph audit-local --allow-extension-publisher microsoft --allow-extension-publisher ms-python

# Create a fake local fixture and run the built-in smoke test
skillseraph demo-fixture --output /tmp/skillseraph-demo
skillseraph smoke-test

# Suppress heuristic (lower-confidence) findings on large repos
skillseraph . --min-confidence high

# Quiet mode for CI logs
skillseraph . --quiet --json-out findings.json
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, `2` error (see
[Exit codes](#exit-codes)).

### Suppressing accepted findings

`--fail-on none` is a local triage scan. A bare suppression still counts:

```markdown
This doc quotes "ignore previous instructions". skillseraph: ignore prompt_injection_override
```

```text
# path globs exclude files entirely
fixtures/**
docs/examples/**

# rule: lines disable a rule everywhere
rule:hypothetical_framing
```

Any other `--fail-on` value is a gate, and so is the admission webhook. A gate honors a suppression only when it names the rule or path, a reason, a role, and an expiry date. The date is inclusive and compared in UTC. `owner` is a role identifier such as `repo-maintainer`. Do not put a personal name, an email address, or a secret in `owner` or `reason`.

```markdown
This doc quotes "ignore previous instructions". skillseraph: ignore prompt_injection_override reason="quoted in project docs" owner=repo-maintainer until=2026-12-31
```

```text
path:fixtures/** reason="vendored project docs" owner=repo-maintainer until=2026-12-31
rule:hypothetical_framing reason="quoted in project docs" owner=repo-maintainer until=2026-12-31
```

The fields are `reason`, then `owner`, then `until`, in that order. A bare comment, a wrong rule id, an email in `owner`, or a past `until` leaves the finding in place. Honored exceptions are listed in the JSON report under `exceptions`.

Or accept a reviewed snapshot with a baseline (only *new* findings surface after):

```bash
# Record the current findings as accepted
skillseraph . --save-baseline .skillseraph-baseline.json

# Later scans suppress those, and fail if the baseline goes stale (governance)
skillseraph . --baseline .skillseraph-baseline.json --baseline-max-age 90
```

---

## What it scans

skillseraph auto-detects and scans config surfaces for these platforms.
`audit-local` also reads Linux and macOS user config for VS Code, Cursor,
Windsurf, Codex, Claude, Continue, Copilot CLI, Gemini CLI, Zed, and opencode.
Shared dot paths (`~/.codex`, `~/.claude`, `~/.continue`, `~/.cursor`,
`~/.copilot`, `~/.gemini`) are the same on both systems, and Zed and opencode
use `~/.config` on both. Claude Desktop is `Library/Application Support/Claude`
on macOS and `.config/Claude` on Linux. APM endpoint evidence keeps the host
and drops URL userinfo. JSON config with comments or trailing commas (JSONC,
as in VS Code, Zed, opencode, and devcontainers) gets the same structural
checks as plain JSON.

| Platform | Files |
|----------|-------|
| Cursor | `.cursor/rules/**`, `**/SKILL.md`, `.cursor/hooks.json`, `.cursor/mcp.json`, `AGENTS.md` |
| VS Code-compatible IDEs | `.vscode/{settings,tasks,launch,extensions}.json`, `*.code-workspace`, `.devcontainer/**` |
| JetBrains IDEs | `.idea/**/*.xml` (run configurations, external tools), `*.iml` |
| Codex | `AGENTS.md`, `.codex/**`, `codex.{json,yaml}` |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/{copilot,instructions,prompts,chatmodes,agents}/**`, `.github/mcp.json`, `.vscode/mcp.json` |
| Gemini CLI | `GEMINI.md`, `.gemini/**` (settings, commands, extensions) |
| opencode | `opencode.json(c)`, `.opencode/**` |
| Zed | `.zed/settings.json` (`context_servers`), `.zed/tasks.json`, `.rules` |
| Claude | `CLAUDE.md`, `.claude/**`, `claude_desktop_config.json`, `.mcp.json` |
| Windsurf | `.windsurfrules`, `.windsurf/**` |
| Cline / Continue | `.clinerules`, `.continue/**` |
| Devin | `devin.md`, `.devin/**` |
| Bedrock Agents | `**/bedrock-agent*.{json,yaml}`, knowledge-base configs |
| LangChain / LangGraph | `**/agents.yaml`, `**/tools.yaml`, prompt templates |
| CrewAI / AutoGPT | `**/agents.yaml`, `**/tasks.yaml`, `**/crew.yaml` |
| Generic | `**/AGENTS.md`, `**/SYSTEM_PROMPT*.md`, planted configs in deps |

---

## Detection categories

| Module | Detects |
|--------|---------|
| `injection` | Instruction override, persona hijack, jailbreak, token-boundary, hidden-comment, multi-language injection, **sleeper/conditional-trigger payloads** (Atlas C1) |
| `exfiltration` | Credential harvesting, data push to URLs, secret-file/env access, DNS/clipboard exfil |
| `permission_bypass` | Sandbox/approval bypass, consent bypass, arbitrary execution, privilege requests |
| `encoding` | Base64/hex blobs, data URIs, unicode-escape chains, `eval(atob())`, ROT13/charcode obfuscation |
| `urls` | Known exfil services, raw-IP/metadata/loopback URLs, MCP server redirects |
| `suppression` | Review/PR suppression, change concealment, stealth operation, user deception |
| `persistence` | Cross-session behavior change, self-config modification, hook/webhook install |
| `tool_abuse` | Dangerous command invocation, path traversal, sensitive-path access, remote bootstrap, **supply-chain** (unpinned installs, postinstall hooks, registry confusion) |
| `authority_fabrication` | Fake maintenance windows, fabricated approvals, pre-authorization claims |
| `runtime_bypass` | Language-runtime evasion of command blocklists, encoded-pipe-to-shell |
| `breakglass` | Embedded override tokens, admission/policy bypass instructions |
| `mcp_servers` | Poisoned MCP server defs in JSON/JSONC, Codex `config.toml`, and servers embedded in Claude, Gemini CLI, Zed, opencode, and Copilot CLI settings (remote/raw-IP URLs, env-credential injection, stdio command exec, TLS disable, wildcard tools, `trust: true` approval bypass) + **tool schema smuggling** (Atlas I3) |
| `automation_triggers` | Wildcard event triggers, shell exec in automations, broad write perms (Atlas J3) |
| `config_inheritance` | Parent traversal, absolute-path includes, remote config fetch, recursive globs (Atlas J5) |
| `skill_invocation` | **Skill invocation hijack** (Atlas J2): callback/redirect on invoke, self-modification, invocation-time override, silent invocation, remote skill pull |
| `ide_integrations` | VS Code, Cursor, and Codex task/debug/user config abuse: remote shell pipes, secret env injection, runtime preloads, extension trust, APM/telemetry collector redirects (including per-signal OTLP endpoints) and inline credentials in OTLP exporter headers (evidence names the headers, never the value) in JSON, YAML, and TOML |
| `extensions` | Installed IDE extension manifests (structural parse): wildcard activation, lifecycle scripts fetching remote code, entry points escaping the install dir, and (opt-in) non-allowlisted publishers |
| `lifecycle` | `devcontainer.json` / `hooks.json` lifecycle commands (structural parse): remote-fetch-to-interpreter payloads split across array/object command forms |
| `jetbrains` | JetBrains `.idea` run configs / external tools / `.iml`: remote-fetch commands and secret env injection in run configurations |
| `supply_chain_trust` | Skill/plugin/tool sources that auto-deploy or skip human review, remote sources flagged `trusted`/`verified`, and remote skill feeds/registries (Atlas D3/J5) |
| `runtime_escape` | Container/orchestrator escape surface: runtime sockets (`docker.sock`, `containerd.sock`), kubelet API, service-account token paths, host-namespace/privileged markers (Atlas J4) |
| `approver_manipulation` | Indirect prompt injection aimed at an automated reviewer/LLM-judge (mark-as-safe, forced ALLOW verdict, "you are the security filter") (OWASP LLM01, Atlas J2/I3) |
| `monitoring_bypass` | Config that disables audit/logging, adds wildcard security exceptions, or disables detection rules (Atlas J3) |

Findings carry a severity (`critical`/`high`/`medium`/`low`), a confidence level
(`high`/`medium`/`low`, filterable with `--min-confidence`), an MCP threat
id (`MCP-T01`–`MCP-T14`), and an Attack Path Atlas domain ID (Domain J primary;
cross-domain C1/I3/D1/D3/D4 where statically detectable).

---

## CI / preventative integration

skillseraph is designed to run as a gate. See [QUICKSTART.md](QUICKSTART.md) for:

- Workstation self-check (`audit-local`) and what it reads on macOS and Linux
- GitHub Actions (composite action and reusable workflow at `@v0`)
- Pre-commit hook
- Kubernetes init-container / admission scanning of mounted configs
- Cursor `beforeShellExecution` hook that blocks agent shell commands while a critical finding is present

---

## Output formats

- **Console** — Rich table, grouped by severity
- **JSON** — full findings with taxonomy/atlas IDs (`--json-out`)
- **SARIF 2.1.0** — GitHub Code Scanning / VS Code (`--sarif`); each result
  carries a `rank` (severity × confidence) and a `confidence` property so Code
  Scanning can sort by it

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No finding at or above `--fail-on` (or `--fail-on none`) |
| `1` | At least one finding at or above `--fail-on` |
| `2` | No verdict: bad option, missing target, unreadable or expired baseline, or an internal error |

Treat `2` as a failed gate too; the Cursor hook in QUICKSTART denies on any
non-zero code.

### JSON report

`--json-out` writes one object. Top-level fields:

| Field | Type | Meaning |
|-------|------|---------|
| `version` | string | skillseraph version |
| `target` | string | Absolute path scanned (the home directory for `audit-local`) |
| `platforms` | list of strings | Platforms detected or requested |
| `files_scanned` | int | Files read |
| `risk_score` | int | Severity-weighted sum of findings |
| `exceptions` | list | Governed suppressions that were honored |
| `findings` | list | Findings after confidence, baseline, and ignore filtering |

Each `findings` entry:

| Field | Type | Meaning |
|-------|------|---------|
| `path` | string | File containing the finding |
| `line` | int or null | 1-based line, when known |
| `check` | string | Rule id, e.g. `mcp_remote_server` |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `title` | string | One-line summary |
| `detail` | string | Matched context |
| `evidence` | string | Redacted excerpt (env values and URL userinfo removed) |
| `platform` | string | Platform the file belongs to |
| `taxonomy_id` | string | MCP threat id (`MCP-T01`–`MCP-T14`, see below) |
| `atlas_id` | string | Attack Path Atlas id, e.g. `J2` |
| `confidence` | string | `high`, `medium`, or `low` |

Each `exceptions` entry (recorded only when a gate is active, i.e. `--fail-on`
is not `none`):

| Field | Type | Meaning |
|-------|------|---------|
| `kind` | string | `rule` (a rule id is suppressed) or `path` (a path pattern is skipped) |
| `scope` | string | The rule id or path pattern |
| `reason` | string | Why it is accepted |
| `owner` | string | Role id accountable for it |
| `until` | string | Expiry date, `YYYY-MM-DD` (inclusive, UTC) |
| `path` | string | File holding the ignore: the scanned file for inline ignores, `.skillseraphignore` otherwise |
| `line` | int or null | Line of an inline ignore, else null |

---

## Standards alignment

Every finding carries two ids:

- `atlas_id`: the agentic-sec [Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
  domain (Domain J, config and automation, is primary).
- `taxonomy_id`: one of these MCP threat categories.

| Id | Threat | Id | Threat |
|----|--------|----|--------|
| `MCP-T01` | Direct prompt injection | `MCP-T08` | Supply chain via content |
| `MCP-T02` | Indirect prompt injection | `MCP-T09` | Agent config tampering |
| `MCP-T03` | Confused deputy | `MCP-T10` | Hallucination-driven destruction |
| `MCP-T04` | Token audience bypass | `MCP-T11` | Cross-tenant memory leak |
| `MCP-T05` | Cross-tool context poisoning | `MCP-T12` | Exfiltration via chaining |
| `MCP-T06` | SSRF via tool | `MCP-T13` | Audit log evasion |
| `MCP-T07` | Secrets in tool output | `MCP-T14` | Persistence via webhook |

Rule packs also cite the related [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
and OWASP MCP Top 10 entries in their header comments. Those references are
not emitted on findings.

---

## Project status & direction

`v0.2.0` released. Available via `install.sh`, a git install
(`uv tool install git+https://github.com/babywyrm/skillseraph`), or a local
checkout. PyPI and the container image are not published yet. See:

- [CHANGELOG.md](CHANGELOG.md) — release history
- [ROADMAP.md](ROADMAP.md) — what's planned and current maturity
- [CONTRIBUTING.md](CONTRIBUTING.md) — checks, adding a detection, what a contribution must not contain
- [SECURITY.md](SECURITY.md) — reporting a vulnerability privately

## License

MIT
