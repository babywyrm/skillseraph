# Roadmap

Where skillseraph is going. Items are grouped by horizon, not hard dates.
Coverage targets track the agentic-sec
[Attack Path Atlas](https://github.com/babywyrm/agentic-sec/blob/main/docs/attack-path-atlas.md)
Domain J (config & automation).

## Maturity at a glance

| Area | State |
|------|-------|
| Multi-platform detection (12 platforms incl. VS Code-compatible IDEs) | **Strong** |
| Data-driven YAML rules (15 packs) | **Strong** — all regex categories YAML-driven |
| Structural (non-regex) parsers | **Strong** — extension manifests, extensions.json, mcp.json env/allowlist fields, and devcontainer/hooks lifecycle commands |
| Confidence scores + `--min-confidence` | **Done** — per-rule confidence, filterable |
| Baseline / allowlist / ignores | **Strong** — baselines, inline ignores, `.skillseraphignore` |
| Local developer self-check (`audit-local`) | **Strong** — user-level IDE configs + installed extension manifests |
| Demo / smoke-test flows | **Done** — `demo-fixture` + `smoke-test` |
| Output (console / JSON / SARIF) | **Strong** — JSON includes confidence |
| CI integration (Action + workflow + PR diff mode) | **Strong** |
| Distribution (PyPI, container image, installer) | **Strong** |
| Kubernetes gating | **Strong** — init-container + admission webhook (opt-in) |
| Policy generation (nullfield) | **Done** |
| Atlas Domain J coverage | **Strong** — J1–J8 done |
| Cross-domain (static) coverage | **Medium** — C1 sleeper, I3 tool-schema, D1/D3/D4 supply chain |

---

## Near-term

- **SARIF confidence mapping** — carry confidence into SARIF `rank`/properties
  so Code Scanning can sort by it.
- **Extension allowlist** — optional list of trusted extension IDs/publishers
  so `audit-local` can flag *unknown* extensions, not just risky manifests.
- **Windows `audit-local` paths** — `%APPDATA%` config/extension locations for
  VS Code / Cursor / Windsurf (currently macOS + Linux only).

## Medium

- **Provenance / signature checks** — flag skills and rules lacking a trusted
  source or signature; optional allowlist of trusted publishers.
- **JetBrains coverage** — `.idea/**` run configurations, external tools, and
  startup tasks as an IDE surface alongside the VS Code family.
- **Severity/confidence tuning pass** — audit every rule against a corpus of
  real repos and assign measured confidence values (currently only the known
  heuristic rules are marked below high).
- **Baseline expiry** — baselines record a timestamp; `--baseline-max-age`
  fails when accepted findings go stale without re-review.

## Horizon

- **Org-wide scanning** — scan all repos in a GitHub org via the API for
  fleet-wide exposure reporting.
- **Unicode / homoglyph deep analysis** — dedicated normalization pass for
  invisible-character and homoglyph injection beyond the current regex.
- **Rule packs** — versioned, shareable rule bundles (community + curated),
  with a contract test that every rule has a fixture.
- **MCP config live cross-check** — optionally hand discovered MCP server URLs
  to mcpnuke for an endpoint scan, bridging static config and live behavior.
- **Extension binary diffing** — compare installed extension contents against
  marketplace-published hashes to catch post-install tampering.

### Shipped (previously roadmap items)

- ~~PyPI publish~~ (`uv tool install skillseraph` / `uvx skillseraph`)
- ~~Inline ignores + `.skillseraphignore`~~
- ~~Confidence scores + `--min-confidence`~~
- ~~Watch mode~~ (`--watch`)
- ~~Atlas J3/J5~~, ~~nullfield policy generation~~, ~~container image~~, ~~diff mode~~
- ~~VS Code-compatible IDE scanning + `audit-local` + extension manifest auditing~~
- ~~Structural parsers for MCP configs + devcontainer/hooks lifecycle commands~~

---

## Contributing detections

Detection patterns live in `src/skillseraph/rules/*.yaml`. To add one:

1. Add a rule (`id`, `pattern`, `severity`, `title`, `taxonomy_id`, `atlas_id`,
   optional `confidence`).
2. Add a fixture under `tests/fixtures/` and a test asserting it fires (and that
   a benign sample does not).
3. Run `uv run pytest` and `uv run ruff check`.

Every rule should map to a public standard (OWASP LLM / OWASP MCP / Atlas domain)
and must not encode any non-public or environment-specific attack details.
