# Roadmap

Where skillseraph is going. Items are grouped by horizon, not hard dates.
Coverage targets track the agentic-sec
[Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
Domain J (config & automation).

## Maturity at a glance

| Area | State |
|------|-------|
| Multi-platform detection (21 platforms incl. VS Code, JetBrains, Zed, Gemini CLI, opencode, Roo Code, Kiro, Amazon Q, Aider, Goose) | **Strong** |
| Data-driven YAML rules (20 packs) | **Strong** — all regex categories YAML-driven |
| Supply-chain / runtime-escape / approver-manipulation / monitoring coverage | **Strong** — config-plane detections mapped to Atlas D3/J4/J2/J3 |
| Structural (non-regex) parsers | **Strong** — extension manifests, extensions.json, mcp.json env/allowlist fields, and devcontainer/hooks lifecycle commands |
| Confidence scores + `--min-confidence` | **Strong** — every rule pack carries calibrated confidence; filterable + SARIF rank |
| Baseline / allowlist / ignores | **Strong** — baselines with expiry, inline ignores, `.skillseraphignore`, governed exceptions on any failing gate |
| Local developer self-check (`audit-local`) | **Strong** — VS Code, Cursor, Windsurf, Codex, Claude, Continue, Copilot CLI, Gemini CLI, Zed, and opencode user configs on Linux and macOS, installed extension manifests, opt-in publisher allowlist |
| Demo / smoke-test flows | **Done** — `demo-fixture` + `smoke-test` |
| Output (console / JSON / SARIF) | **Strong** — JSON includes confidence |
| CI integration (Action + workflow + PR diff mode) | **Strong** |
| Distribution (PyPI, container image, installer) | **Thin** — `install.sh` and git installs work; the v0.2.0 PyPI upload failed at OIDC (no trusted publisher); the image builds and is tested in CI, but GHCR visibility is undecided |
| Kubernetes gating | **Strong** — init-container + admission webhook (opt-in) |
| Policy generation (nullfield) | **Done** |
| Atlas Domain J coverage | **Strong** — J1–J8 done |
| Cross-domain (static) coverage | **Medium** — C1 sleeper, I3 tool-schema, D1/D3/D4 supply chain |

---

> **Supported platforms:** Linux and macOS are the primary (and only planned)
> targets. Windows `%APPDATA%` support is intentionally out of scope.

## Near-term

- **Repair distribution.** Register the PyPI trusted publisher and cut the
  next release, which also moves `v0` past the June `v0.2.0` commit. Decide
  whether the GHCR image is public, then point the Kubernetes examples at it.
  The Dockerfile build order is fixed.
- **Provenance / signature checks** — flag skills and rules lacking a trusted
  source or signature; optional allowlist of trusted publishers.

## Medium

- **A2A agent cards** — static checks on `.well-known/agent.json` for injected
  descriptions and external endpoints, as tool-schema smuggling does for MCP.
- **Redacted literal-secret detection** — flag literal tokens in MCP `env`
  blocks and client settings, reporting key names only, never values.
- **Change-only `audit-local`** — snapshot a workstation and report only what
  changed since, so a new MCP server or extension stands out.
- **Inventory output** — `--inventory` lists every MCP server, extension, hook,
  and rule file found, without judging them, for fleet audits.

- **Rule packs** — versioned, shareable rule bundles (community + curated),
  with a firing sample for every rule (today every rule id must appear in a
  test, which `test_rule_coverage.py` enforces).
- **Unicode / homoglyph deep analysis** — dedicated normalization pass for
  invisible-character and homoglyph injection beyond the current regex.

## Horizon

- **Org-wide scanning** — scan all repos in a GitHub org via the API for
  fleet-wide exposure reporting.
- **MCP config live cross-check** — optionally hand discovered MCP server URLs
  to mcpnuke for an endpoint scan, bridging static config and live behavior.
- **Extension binary diffing** — compare installed extension contents against
  marketplace-published hashes to catch post-install tampering.
- **pre-commit hook** — ship `.pre-commit-hooks.yaml` so repos can gate on
  skillseraph without CI changes.
- **Rule test command** — `skillseraph rules test` runs a contributed rule's
  positive and negative samples without the repo's pytest setup.

### Shipped (previously roadmap items)

- ~~Inline ignores + `.skillseraphignore`~~
- ~~Confidence scores + `--min-confidence`~~
- ~~Watch mode~~ (`--watch`)
- ~~Atlas J3/J5~~, ~~nullfield policy generation~~, ~~diff mode~~
- ~~VS Code-compatible IDE scanning + `audit-local` + extension manifest auditing~~
- ~~Structural parsers for MCP configs + devcontainer/hooks lifecycle commands~~
- ~~Extension publisher allowlist (`--allow-extension-publisher`)~~
- ~~JetBrains `.idea` run configuration / external tool coverage~~
- ~~SARIF confidence mapping (`rank` + confidence properties)~~
- ~~Rule confidence tuning pass across all packs~~
- ~~Baseline expiry (`--baseline-max-age`)~~
- ~~Governed exceptions (reason, role, expiry) on failing gates, with JSON evidence~~
- ~~Agent permission modes (Claude, Codex, Gemini CLI, Cursor CLI)~~
- ~~Hooks in client settings (Claude, Gemini CLI, Codex), including HTTP hooks~~
- ~~MCP server version pinning~~
- ~~Roo Code, Kiro, Amazon Q Developer, Aider, and Goose~~

---

## Contributing detections

See [CONTRIBUTING.md](CONTRIBUTING.md).
