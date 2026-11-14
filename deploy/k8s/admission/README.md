# skillseraph Admission Webhook

Optional deploy-time gate: rejects ConfigMap creates/updates in labeled namespaces
when any `data` or `binaryData` key has findings at or above the severity
threshold.

## How it works

1. Namespace is labeled `skillseraph.io/scan: "true"` (opt-in).
2. A ConfigMap is created/updated in that namespace.
3. The webhook reads every `data` key and every base64-decoded `binaryData`
   key. Key names do not limit the scan, because a volume's `items[].path`
   can mount any key at an agent config path.
4. Each key is scanned by skillseraph's rule engine.
5. If findings at/above `FAIL_ON` (default: `high`) are found, the request is
   rejected with a 403 and a message listing the findings.

The webhook is always a gate. An inline `skillseraph: ignore <rule>` comment
inside a ConfigMap value counts only when it gives a reason, a role, and an
unexpired date (`reason="…" owner=<role> until=YYYY-MM-DD`). A bare ignore
does not stop a rejection.

Build the image first and load it into the cluster
(`docker build -t skillseraph:local .`), then set that image in
`manifests.yaml`. No release image is published yet.

## Deploy

Requires cert-manager (for automatic TLS) or manual cert provisioning.

```bash
# With cert-manager installed:
kubectl apply -f deploy/k8s/admission/manifests.yaml

# Label a namespace to opt in:
kubectl label ns my-agents skillseraph.io/scan=true

# Test — this should be REJECTED:
kubectl apply -n my-agents -f deploy/k8s/configmap-poisoned.yaml
```

## Configuration

| Env | Default | Description |
|-----|---------|-------------|
| `FAIL_ON` | `high` | Severity threshold for rejection |
| `LISTEN_PORT` | `8443` | Webhook listen port |
| `TLS_CERT_FILE` | `/certs/tls.crt` | TLS certificate path |
| `TLS_KEY_FILE` | `/certs/tls.key` | TLS key path |

The webhook exits at startup if `FAIL_ON` is not one of `critical`, `high`,
`medium`, `low`, `any`, or `none`, or if the TLS cert or key is missing. With
a fail-open policy, a typo or a plaintext listener the API server cannot
reach would otherwise admit everything. Malformed or oversized (over 4 MiB)
requests get a 400 or 413, and each connection runs in its own thread with
a 5-second timeout, so one stalled client cannot hold up reviews.

## Failure policy

Set to `Ignore` (fail-open) so the webhook never blocks cluster operations if it's
unhealthy. For stricter enforcement, change to `Fail` — but ensure the webhook is
highly available first.
