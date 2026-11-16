# Security policy

## Supported versions

Fixes land on `main` and ship in the next `0.x` release. Only the latest
release (the `v0` tag) is supported.

## Reporting a vulnerability

Use GitHub private vulnerability reporting:
[report a vulnerability](https://github.com/babywyrm/skillseraph/security/advisories/new)
(or the repository's **Security** tab, then **Report a vulnerability**). Do
not open a public issue.

Include the version or commit, the command or config that triggers it, and
the impact. A minimal config file is ideal; a working exploit is not needed.
Redact tokens, hostnames, and anything else from your own environment.

You should get an acknowledgement within a week. Once a fix ships, the
advisory is published with credit unless you ask otherwise.

## Verifying what you run

Release files (from v0.3.0) and the container image carry signed build
provenance from this repository's workflows. Check it with the GitHub CLI:

```bash
gh attestation verify skillseraph-0.3.0-py3-none-any.whl --repo babywyrm/skillseraph
gh attestation verify oci://ghcr.io/babywyrm/skillseraph:latest --repo babywyrm/skillseraph
```

PyPI uploads also carry the publish step's attestations, shown on the
project's PyPI page. The image is scanned for known CVEs on every change
and weekly; results are in the repository's code scanning alerts.

## In scope

- A crafted input that makes skillseraph run code, write outside its scan or
  temp directory, or read files it was not pointed at.
- The admission webhook, the composite action, `install.sh`, and the
  container image.
- Secrets or credentials leaking into console, JSON, or SARIF output.
- A gate that passes when it should fail (a bypass of `--fail-on`, governed
  exceptions, or baselines).

## Out of scope

- A poisoned config that skillseraph does not detect. That is a detection
  gap: open a normal issue or pull request with a generic sample (see
  [CONTRIBUTING.md](CONTRIBUTING.md)).
- Findings in the deliberately poisoned files under `tests/fixtures/`.
