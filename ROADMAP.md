# Roadmap

Where skillseraph is going. Items are grouped by horizon, not hard dates.
Coverage targets track the agentic-sec
[Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
Domain J (config & automation).

## Maturity at a glance

| Area | State |
|------|-------|
| Multi-platform detection (11 platforms) | **Strong** |
| Data-driven YAML rules | **Strong** |
| Baseline / allowlist | **Medium** — file-level baseline; no inline ignores yet |
| Output (console / JSON / SARIF) | **Strong** |
| CI integration (Action + workflow) | **Medium** — works; not yet on a registry |
| Distribution (PyPI / container image) | **Thin** — source/git only |
| Policy generation (nullfield) | **Not started** |
| Atlas Domain J coverage | **Partial** — J1/J4/J6/J7/J8 done; J3/J5 open |

---

## Near-term

- **PyPI publish** — `pip install skillseraph` / `uvx skillseraph` without git.
- **Container image** (GHCR) — `ghcr.io/babywyrm/skillseraph` so the Kubernetes
  init-container example in QUICKSTART runs out of the box.
- **Inline ignores** — `# skillseraph: ignore <rule>` comments and a
  `.skillseraphignore` file for path/rule exclusions, complementing baselines.
- **Diff mode** — `--changed-only` to scan just the files in a PR diff (fast CI).
- **Publish the Action to the Marketplace** so `uses: babywyrm/skillseraph@v1` is
  first-class.

## Medium

- **Atlas J3 / J5 coverage** — automation-trigger abuse (J3) and config-inheritance
  escalation (J5): scan automation/event definitions and parent→child config
  inheritance for scope widening.
- **nullfield policy generation** — `--generate-policy` to emit a NullfieldPolicy
  from findings, closing the scan → enforce loop with the rest of the ecosystem.
- **Provenance / signature checks** — flag skills and rules lacking a trusted
  source or signature; optional allowlist of trusted publishers.
- **Structural parsers** — parse JSON/YAML configs (MCP server defs, hooks)
  structurally rather than line-regex, to cut false positives and catch
  field-level issues (e.g. server URL redirects, tool allowlist tampering).
- **Severity tuning + confidence scores** — per-rule confidence and a
  `--min-confidence` filter to reduce noise on large repos.

## Horizon

- **Watch mode** — `--watch` for agent workloads that fetch skills/configs at
  runtime (sidecar use case).
- **Org-wide scanning** — scan all repos in a GitHub org via the API for
  fleet-wide exposure reporting.
- **Unicode / homoglyph deep analysis** — dedicated normalization pass for
  invisible-character and homoglyph injection beyond the current regex.
- **Rule packs** — versioned, shareable rule bundles (community + curated),
  with a contract test that every rule has a fixture.
- **MCP config live cross-check** — optionally hand discovered MCP server URLs
  to mcpnuke for an endpoint scan, bridging static config and live behavior.

---

## Contributing detections

Detection patterns live in `src/skillseraph/rules/*.yaml`. To add one:

1. Add a rule (`id`, `pattern`, `severity`, `title`, `taxonomy_id`, `atlas_id`).
2. Add a fixture under `tests/fixtures/` and a test asserting it fires (and that
   a benign sample does not).
3. Run `uv run pytest` and `uv run ruff check`.

Every rule should map to a public standard (OWASP LLM / OWASP MCP / Atlas domain)
and must not encode any non-public or environment-specific attack details.
