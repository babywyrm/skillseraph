# skillseraph Admission Webhook

Optional deploy-time gate: rejects ConfigMap creates/updates in labeled namespaces
when their data keys contain agent-config patterns (AGENTS.md, SKILL.md, hooks.json,
etc.) with findings at or above the severity threshold.

## How it works

1. Namespace is labeled `skillseraph.io/scan: "true"` (opt-in).
2. A ConfigMap is created/updated in that namespace.
3. The webhook extracts data keys matching agent-config patterns.
4. Each matching key is scanned by skillseraph's rule engine.
5. If findings at/above `FAIL_ON` (default: `high`) are found, the request is
   rejected with a 403 and a message listing the findings.

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

## Failure policy

Set to `Ignore` (fail-open) so the webhook never blocks cluster operations if it's
unhealthy. For stricter enforcement, change to `Fail` — but ensure the webhook is
highly available first.
