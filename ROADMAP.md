# Roadmap

Where skillseraph is going. Items are grouped by horizon, not hard dates.
Coverage targets track the agentic-sec
[Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
Domain J (config & automation).

## Maturity at a glance

| Area | State |
|------|-------|
| Multi-platform detection (11 platforms) | **Strong** |
| Data-driven YAML rules (11 packs) | **Strong** |
| Baseline / allowlist | **Medium** — file-level baseline; no inline ignores yet |
| Output (console / JSON / SARIF) | **Strong** |
| CI integration (Action + workflow + PR diff mode) | **Strong** — composite action, reusable workflow, `--changed-only` |
| Distribution (container image) | **Strong** — Dockerfile + GHCR push in CI; PyPI pending |
| Kubernetes gating | **Strong** — init-container + admission webhook (opt-in) |
| Policy generation (nullfield) | **Done** — `--generate-policy` emits NullfieldPolicy |
| Atlas Domain J coverage | **Strong** — J1/J3/J4/J5/J6/J7/J8 done |

---

## Near-term

- **PyPI publish** — `pip install skillseraph` / `uvx skillseraph` without git.
- **Inline ignores** — `# skillseraph: ignore <rule>` comments and a
  `.skillseraphignore` file for path/rule exclusions, complementing baselines.
- **Publish the Action to the Marketplace** — tag `v0.1.0` + floating `v1` so
  `uses: babywyrm/skillseraph@v1` is first-class.

## Medium

- ~~Atlas J3/J5~~ **Done** (automation_triggers.yaml, config_inheritance.yaml).
- ~~nullfield policy generation~~ **Done** (`--generate-policy`).
- ~~Container image~~ **Done** (Dockerfile + GHCR push in CI).
- ~~Diff mode~~ **Done** (`--changed-only` + `--files-from`).
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
