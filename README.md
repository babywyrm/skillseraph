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

# Quiet mode for CI logs
skillseraph . --quiet --json-out findings.json
```

Exit codes: `0` clean, `1` findings at/above `--fail-on`, non-zero on error.

---

## What it scans

skillseraph auto-detects and scans config surfaces for these platforms:

| Platform | Files |
|----------|-------|
| Cursor | `.cursor/rules/**`, `**/SKILL.md`, `.cursor/hooks.json`, `.cursor/mcp.json`, `AGENTS.md` |
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
| `injection` | Instruction override, persona hijack, jailbreak, token-boundary, hidden-comment, multi-language injection |
| `exfiltration` | Credential harvesting, data push to URLs, secret-file/env access, DNS/clipboard exfil |
| `permission_bypass` | Sandbox/approval bypass, consent bypass, arbitrary execution, privilege requests |
| `encoding` | Base64/hex blobs, data URIs, unicode-escape chains (obfuscated payloads) |
| `urls` | Known exfil services, raw-IP/metadata/loopback URLs, MCP server redirects |
| `suppression` | Review/PR suppression, change concealment, stealth operation, user deception |
| `persistence` | Cross-session behavior change, self-config modification, hook/webhook install |
| `tool_abuse` | Dangerous command invocation, path traversal, sensitive-path access, remote bootstrap |
| `authority_fabrication` | Fake maintenance windows, fabricated approvals, pre-authorization claims |
| `runtime_bypass` | Language-runtime evasion of command blocklists, encoded-pipe-to-shell |
| `breakglass` | Embedded override tokens, admission/policy bypass instructions |

Findings carry a severity (`critical`/`high`/`medium`/`low`), a taxonomy ID
(OWASP MCP / MCP-T), and an Attack Path Atlas domain ID.

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
- **SARIF 2.1.0** — GitHub Code Scanning / VS Code (`--sarif`)

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
