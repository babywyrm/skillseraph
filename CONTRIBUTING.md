# Contributing

skillseraph runs on Linux and macOS with Python 3.11+. Windows is out of scope.

## Setup and checks

```bash
uv sync --extra dev
uv run ruff check src/ tests/
uv run mypy
uv run pytest
uv run skillseraph . --fail-on critical    # dogfood scan
```

Container integration (needs Docker):

```bash
docker build -t skillseraph:ci .
SKILLSERAPH_CONTAINER=1 uv run pytest tests/test_container_integration.py
```

Workflow changes: `uvx zizmor@1.32.0 --offline .` must report no findings.
Third-party actions are pinned to a commit SHA with the version in a comment.

CI runs all of the above on Ubuntu and macOS for Python 3.11–3.13.

## Adding a detection

Rules live in `src/skillseraph/rules/*.yaml`.

1. Add a rule: `id`, `pattern`, `severity`, `title`, `detail`, `taxonomy_id`
   (`MCP-T01`–`MCP-T14`), `atlas_id`, and optional `confidence`.
2. Add a sample that fires to `tests/test_rule_coverage.py`, and a benign
   sample that does not fire next to the related tests.
   `test_every_yaml_rule_is_exercised_by_a_test` fails if a rule id appears in
   no test.
3. If the rule needs structure (JSON, TOML), add the check under
   `src/skillseraph/checks/` and type it; `mypy --strict` runs in CI.
4. Add a line to `CHANGELOG.md` under `Unreleased`, and update the README
   tables if a category or platform changes.

## What a contribution must not contain

This is a public, community project.

- No secrets, tokens, flags, real hostnames, IPs, or credentials, even
  expired ones. Use `evil.example`, `collector.example`, and similar.
- No personal names, emails, or machine paths in code, fixtures, or docs.
  Use role ids such as `repo-maintainer` for owners.
- No exploit code or attack procedures. A detection describes the config
  pattern, not how to abuse a specific system.
- No details of private, unreleased, or environment-specific targets. Every
  rule maps to a public standard or the public Atlas.

## Pull requests and commits

One logical change per pull request, with its tests and doc updates in the
same commits. Commit subjects are imperative, capitalized after the type
prefix, and at most 50 characters (`fix: reject unsafe webhook keys`). The
body explains why.

Security issues go through [SECURITY.md](SECURITY.md), not pull requests.
