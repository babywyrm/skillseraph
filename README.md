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
SKILLSERAPH_REF=v0.1.0 curl -fsSL https://raw.githubusercontent.com/babywyrm/skillseraph/main/install.sh | sh
```

### PyPI

```bash
# Requires uv (https://docs.astral.sh/uv/getting-started/installation/)
uv tool install skillseraph          # global install → skillseraph on PATH
pip install skillseraph              # pip also works (Python 3.11+)
```

### Run without installing (no clone required)

```bash
uvx skillseraph .                    # ephemeral run, nothing persisted
uvx --from git+https://github.com/babywyrm/skillseraph skillseraph .   # latest main
```

### From source (development)

```bash
git clone https://github.com/babywyrm/skillseraph
cd skillseraph
uv tool install .         # global install from local checkout
# or: uv sync && uv run skillseraph --version   (dev mode, no install)
```

Runs on Linux and macOS. Pure Python (3.11+), no system dependencies.

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

# Developer self-check for local VS Code-compatible IDE config
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

Exit codes: `0` clean, `1` findings at/above `--fail-on`, non-zero on error.

### Suppressing accepted findings

Inline, on the offending line (suppresses one named rule):

```markdown
This doc quotes "ignore previous instructions". <!-- skillseraph: ignore prompt_injection_override -->
```

Repo-wide, via a `.skillseraphignore` file at the scan root:

```text
# path globs exclude files entirely
fixtures/**
docs/examples/**

# rule: lines disable a rule everywhere
rule:hypothetical_framing
```

---

## What it scans

skillseraph auto-detects and scans config surfaces for these platforms:

| Platform | Files |
|----------|-------|
| Cursor | `.cursor/rules/**`, `**/SKILL.md`, `.cursor/hooks.json`, `.cursor/mcp.json`, `AGENTS.md` |
| VS Code-compatible IDEs | `.vscode/{settings,tasks,launch,extensions}.json`, `*.code-workspace`, `.devcontainer/**` |
| JetBrains IDEs | `.idea/**/*.xml` (run configurations, external tools), `*.iml` |
| Codex | `AGENTS.md`, `.codex/**`, `codex.{json,yaml}` |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/copilot/**` |
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
| `mcp_servers` | Poisoned MCP server defs (remote/raw-IP URLs, env-credential injection, stdio command exec, TLS disable, wildcard tools) + **tool schema smuggling** (Atlas I3) |
| `automation_triggers` | Wildcard event triggers, shell exec in automations, broad write perms (Atlas J3) |
| `config_inheritance` | Parent traversal, absolute-path includes, remote config fetch, recursive globs (Atlas J5) |
| `skill_invocation` | **Skill invocation hijack** (Atlas J2): callback/redirect on invoke, self-modification, invocation-time override, silent invocation, remote skill pull |
| `ide_integrations` | VS Code-compatible task/debug/user config abuse: remote shell pipes, secret env injection, runtime preloads, extension trust, APM/telemetry collector redirects |
| `extensions` | Installed IDE extension manifests (structural parse): wildcard activation, lifecycle scripts fetching remote code, entry points escaping the install dir, and (opt-in) non-allowlisted publishers |
| `lifecycle` | `devcontainer.json` / `hooks.json` lifecycle commands (structural parse): remote-fetch-to-interpreter payloads split across array/object command forms |
| `jetbrains` | JetBrains `.idea` run configs / external tools / `.iml`: remote-fetch commands and secret env injection in run configurations |

Findings carry a severity (`critical`/`high`/`medium`/`low`), a confidence level
(`high`/`medium`/`low`, filterable with `--min-confidence`), a taxonomy ID
(OWASP MCP / MCP-T), and an Attack Path Atlas domain ID (Domain J primary;
cross-domain C1/I3/D1/D3/D4 where statically detectable).

---

## CI / preventative integration

skillseraph is designed to run as a gate. See [QUICKSTART.md](QUICKSTART.md) for:

- GitHub Actions (reusable workflow + composite action + GitHub Marketplace)
- Pre-commit hook
- Kubernetes init-container / admission scanning of mounted configs
- IDE agent hooks (scan before an agentic session starts)

---

## Output formats

- **Console** — Rich table, grouped by severity
- **JSON** — full findings with taxonomy/atlas IDs (`--json-out`)
- **SARIF 2.1.0** — GitHub Code Scanning / VS Code (`--sarif`); each result
  carries a `rank` (severity × confidence) and a `confidence` property so Code
  Scanning can sort by it

---

## Standards alignment

Findings map to:

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- OWASP MCP Top 10 (MCP01–MCP10)
- The agentic-sec [Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md) (Domain J: config & automation)

---

## Project status & direction

`v0.1.0` released. Available via `install.sh`, PyPI (`uv tool install skillseraph`),
`uvx`, and Docker (GHCR). See:

- [CHANGELOG.md](CHANGELOG.md) — release history
- [ROADMAP.md](ROADMAP.md) — what's planned and current maturity

## License

MIT
