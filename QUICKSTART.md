# skillseraph Quickstart

From install to a working gate on a repo, a workstation, CI, and a cluster.
Linux and macOS only.

---

## 1. Install

skillseraph runs on `uv`. It is not on PyPI yet.

```bash
# Installs uv if missing, then skillseraph from the v0.2.0 tag
SKILLSERAPH_REF=v0.2.0 curl -fsSL https://raw.githubusercontent.com/babywyrm/skillseraph/main/install.sh | sh

# Or, with uv already installed
uv tool install git+https://github.com/babywyrm/skillseraph@v0.2.0

# Or run once without installing
uvx --from git+https://github.com/babywyrm/skillseraph@v0.2.0 skillseraph .
```

Without `SKILLSERAPH_REF`, `install.sh` installs `main`. Features listed under
`[Unreleased]` in [CHANGELOG.md](CHANGELOG.md) are on `main` and not in `v0.2.0`.

From source:

```bash
git clone https://github.com/babywyrm/skillseraph
cd skillseraph
uv tool install .
```

---

## 2. Scan a repo

```bash
skillseraph .
```

The console shows each finding's severity, rule id, file and line, and title,
then a summary with the risk score and the `--fail-on` threshold. Platforms
are auto-detected from the files present (`.cursor/`, `.codex/`, `.claude/`,
`.vscode/`, `AGENTS.md`, `SKILL.md`, and the rest in [README.md](README.md)).

Exit codes: `0` when nothing is at or above `--fail-on`, `1` when something is,
and `2` when there is no verdict (bad option, missing target, unreadable or
expired baseline). Treat `2` as a failed gate.

For a report a tool can read:

```bash
skillseraph . --fail-on none --json-out findings.json --sarif findings.sarif
```

---

## 3. Check your workstation

`audit-local` reads agent, IDE, and APM settings in your home directory. It is
the same scan, pointed at user-level config instead of a repo.

```bash
skillseraph audit-local
skillseraph audit-local --json-out workstation.json
```

It reads these files and no others:

| Client | macOS | Linux |
|--------|-------|-------|
| VS Code, Cursor, Windsurf | `~/Library/Application Support/<App>/User/` settings, tasks, keybindings, snippets | `~/.config/<App>/User/` (same files) |
| Installed IDE extensions | `~/.vscode`, `~/.cursor`, `~/.windsurf` `extensions/*/package.json` | same |
| Cursor agent | `~/.cursor/mcp.json`, `hooks.json`, `cli-config.json`, `argv.json` | same |
| Codex | `~/.codex/config.toml`, `~/.codex/hooks.json`, `~/.codex/rules/`, `~/.codex/skills/` | same |
| Claude Code | `~/.claude/settings.json`, `settings.local.json`, `CLAUDE.md` | same |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Continue | `~/.continue/config.json`, `config.yaml` | same |
| VS Code / Copilot MCP | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` | same |
| Gemini CLI | `~/.gemini/settings.json`, `GEMINI.md`, `commands/`, `extensions/*/gemini-extension.json` | same |
| Zed | `~/.config/zed/settings.json`, `tasks.json` | same |
| opencode | `~/.config/opencode/opencode.json(c)`, `AGENTS.md`, `agents/`, `commands/` | same |
| Roo Code | `Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/{mcp_settings.json,custom_modes.yaml}`, `~/.roo/rules/` | `~/.config/Code/User/globalStorage/…` (same files) |
| Kiro | `~/.kiro/settings/mcp.json`, `steering/`, `agents/` | same |
| Amazon Q Developer | `~/.aws/amazonq/mcp.json`, `default.json`, `cli-agents/` | same |
| Aider | `~/.aider.conf.yml` | same |
| Goose | `~/.config/goose/config.yaml`, `.goosehints` | same |

It does not read session logs, auth files, history, or databases. Reports list
credential env var names, never their values, and drop the user:password part
of collector URLs.

On a workstation it flags MCP servers that are remote or launch shell
commands, servers marked `trust: true` (Gemini CLI skips every tool
confirmation for them), credentials passed to MCP servers, runtime preloads such as
`NODE_OPTIONS=--require`, and APM endpoints (OpenTelemetry, Sentry, Datadog,
New Relic, Honeycomb, Elastic) that point anywhere other than localhost.

To flag extensions from publishers you do not trust:

```bash
skillseraph audit-local --allow-extension-publisher microsoft --allow-extension-publisher ms-python
```

For an incident, keep the report with the time it was taken:

```bash
skillseraph audit-local --fail-on none --json-out "workstation-$(date -u +%Y%m%dT%H%M%SZ).json"
```

---

## 4. Tune the gate

```bash
skillseraph . --fail-on critical          # loosest gate
skillseraph . --fail-on any               # strictest
skillseraph . --min-confidence high       # drop heuristic findings
skillseraph . --fail-on none              # report only
```

`--fail-on high` (the default) trips on `high` and `critical`.

When `--fail-on` is anything except `none`, a suppression counts only if it
gives a reason, a role, and an expiry date:

```markdown
This page quotes "ignore previous instructions". skillseraph: ignore prompt_injection_override reason="quoted in project docs" owner=repo-maintainer until=2026-12-31
```

A bare `skillseraph: ignore <rule>` still works with `--fail-on none`. Details,
`.skillseraphignore`, and baselines are in [README.md](README.md).

---

## 5. GitHub Actions

`@v0` is the major tag the release workflow moves on each `0.x` release.

### Option A — composite action

```yaml
name: skillseraph
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0   # changed-only diff needs the base commit
      - uses: babywyrm/skillseraph@v0
        with:
          fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: skillseraph.sarif
```

The action writes `skillseraph.sarif` and `skillseraph.json`. On a pull
request it scans only the changed files. Other inputs: `path`, `platform`,
`include-deps`, `changed-only`, `baseline`, `baseline-max-age` (days; an older
baseline fails the run), and `min-confidence` (`low`, `medium`, `high`). See
`action.yml` for defaults.

### Option B — uv, no action

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
      - uses: astral-sh/setup-uv@v10.3.3
      - run: |
          uvx --from git+https://github.com/babywyrm/skillseraph@v0.2.0 skillseraph . \
            --fail-on high \
            --sarif skillseraph.sarif \
            --json-out skillseraph.json
      - if: always()
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: skillseraph.sarif
```

### Option C — reusable workflow

```yaml
name: agent-config-security
on: [pull_request]
jobs:
  skillseraph:
    uses: babywyrm/skillseraph/.github/workflows/scan.yml@v0
    with:
      fail-on: high
      paths: "."
```

---

## 6. Pre-commit hook

```yaml
repos:
  - repo: local
    hooks:
      - id: skillseraph
        name: skillseraph agent-config scan
        entry: skillseraph
        args: ["--fail-on", "high", "--quiet"]
        language: system
        pass_filenames: false
        files: '(AGENTS\.md|CLAUDE\.md|SKILL\.md|\.mdc|\.cursor/.*|\.codex/.*|\.claude/.*|\.vscode/.*|copilot-instructions\.md)$'
```

```bash
pre-commit install
```

The hook scans the whole repo when a matching file is staged. It uses the
gate rules from section 4.

---

## 7. Kubernetes

Build the image and load it into your cluster. CI builds it on every pull
request; no release image is published yet.

```bash
docker build -t skillseraph:local .
kind load docker-image skillseraph:local   # or your cluster's image import
```

To run the image directly and write a report into a mounted directory, run
it as your own user. On Linux the mount keeps host ownership, and the image's
default user cannot write to it.

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan:ro" -v "$PWD/out:/out" \
  skillseraph:local /scan --fail-on high --json-out /out/skillseraph.json
```

Scan mounted agent configs before the agent starts. If the init container
exits non-zero, the pod never starts.

```yaml
initContainers:
  - name: skillseraph-gate
    image: skillseraph:local
    args: ["/configs", "--fail-on", "high"]
    volumeMounts:
      - name: agent-configs
        mountPath: /configs
        readOnly: true
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

That security context is exercised in CI by
`tests/test_container_integration.py`. A full example is in
`deploy/k8s/init-container-example.yaml`, and `deploy/k8s/test-gate.sh` checks
it on a live cluster. To reject poisoned ConfigMaps at admission time, see
[deploy/k8s/admission/README.md](deploy/k8s/admission/README.md).

For configs that change at runtime, run `skillseraph /configs --watch` in a
sidecar. It re-scans on change and exits non-zero when a finding crosses
`--fail-on`.

---

## 8. Cursor hook

Block the agent's shell commands while the workspace has a critical finding.
`.cursor/hooks.json`:

```json
{
  "version": 1,
  "hooks": {
    "beforeShellExecution": [
      {
        "command": ".cursor/hooks/skillseraph-gate.sh"
      }
    ]
  }
}
```

`.cursor/hooks/skillseraph-gate.sh`:

```bash
#!/bin/sh
cat >/dev/null
if skillseraph . --fail-on critical --quiet; then
  echo '{"permission":"allow"}'
else
  echo '{"permission":"deny","user_message":"skillseraph blocked shell: a critical finding is in this workspace. Run skillseraph . --fail-on critical to see it.","agent_message":"Shell blocked by the skillseraph workspace gate."}'
fi
```

```bash
chmod +x .cursor/hooks/skillseraph-gate.sh
```

The scan runs before every agent shell command. If `skillseraph` is not on
the hook's `PATH`, the script denies, so install it before enabling the hook.

---

## Where to go next

- [README.md](README.md) — platforms, detection categories, suppressions, output formats
- [CHANGELOG.md](CHANGELOG.md) — what is released and what is on `main`
- [Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md) — the threat map rules are tagged with
- New rules go in `src/skillseraph/rules/*.yaml`, with a test under `tests/`
