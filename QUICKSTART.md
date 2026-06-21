# skillseraph Quickstart

Get from zero to a passing security gate in five minutes.

---

## 1. Install & first scan

```bash
uv tool install skillseraph        # or: git clone … && uv sync
skillseraph .                      # scan current repo
```

You'll get a table of findings grouped by severity, plus a summary line with the
risk score and the `--fail-on` threshold.

Try it against a known-bad sample to see output:

```bash
skillseraph . --platform cursor -v
```

---

## 2. Tune the gate

```bash
# Only fail on critical findings (loosest gate)
skillseraph . --fail-on critical

# Fail on any finding at all (strictest)
skillseraph . --fail-on any

# Never fail; report only (for dashboards)
skillseraph . --fail-on none --json-out findings.json
```

Severity ladder: `critical` > `high` > `medium` > `low`. `--fail-on high`
(the default) trips on `high` and `critical`.

---

## 3. GitHub Actions (recommended)

### Option A — composite action (drop-in)

Add `.github/workflows/skillseraph.yml` to any repo that contains agent configs:

```yaml
name: skillseraph
on:
  pull_request:
    paths:
      - "**/AGENTS.md"
      - "**/CLAUDE.md"
      - "**/SKILL.md"
      - ".cursor/**"
      - ".github/copilot-instructions.md"
      - "**/*.mdc"
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v5

      - name: Run skillseraph
        run: |
          uvx skillseraph . \
            --fail-on high \
            --sarif skillseraph.sarif \
            --json-out skillseraph.json

      - name: Upload SARIF to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skillseraph.sarif
```

Findings show up inline on the PR via GitHub Code Scanning, and the job fails
if anything reaches `high`.

### Option B — reusable workflow

This repo ships a reusable workflow at `.github/workflows/scan.yml`. From a
consuming repo:

```yaml
name: agent-config-security
on: [pull_request]
jobs:
  skillseraph:
    uses: babywyrm/skillseraph/.github/workflows/scan.yml@main
    with:
      fail-on: high
      paths: "."
```

---

## 4. Pre-commit hook (catch it before it's committed)

Add to `.pre-commit-config.yaml`:

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
        files: '(AGENTS\.md|CLAUDE\.md|SKILL\.md|\.mdc|\.cursor/.*|copilot-instructions\.md)$'
```

```bash
pre-commit install
```

Now poisoned configs are blocked at commit time.

---

## 5. Kubernetes (agentic workloads)

If your agents load skills/configs from mounted `ConfigMap`s or fetched at
runtime, scan them in an init container before the agent boots:

```yaml
initContainers:
  - name: skillseraph-gate
    image: ghcr.io/babywyrm/skillseraph:latest
    args: ["/configs", "--fail-on", "high"]
    volumeMounts:
      - name: agent-configs
        mountPath: /configs
        readOnly: true
```

If skillseraph exits non-zero, the init container fails and the agent pod never
starts with poisoned configs.

> For continuous monitoring of configs fetched at runtime, run skillseraph in a
> sidecar `--watch` loop (planned) or trigger it from your agent's
> `beforeAgentStart` hook.

---

## 6. IDE agent hook (Cursor example)

Scan the workspace before an agentic session begins. In `.cursor/hooks.json`:

```json
{
  "hooks": [
    {
      "event": "beforeAgentStart",
      "command": "skillseraph . --fail-on critical --quiet"
    }
  ]
}
```

A non-zero exit blocks the session if a critical poisoning pattern is present.

---

## Where to go next

- [README.md](README.md) — full detection category reference
- [Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md) — Domain J (config & automation) threat map
- Contribute detection rules: add patterns under `src/skillseraph/rules/*.yaml`
  and a fixture + test under `tests/`.
