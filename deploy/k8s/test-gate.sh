#!/usr/bin/env bash
# test-gate.sh — validate the skillseraph init-container gate on a live cluster.
#
# Applies both a poisoned and a clean ConfigMap, then creates the gated pod and
# asserts: poisoned -> init fails; clean -> pod starts.
#
# Prerequisites: kubectl access to a cluster with the skillseraph image available
# (ghcr.io/babywyrm/skillseraph:latest, or build locally and import to k3s/kind).
#
# Usage:
#   IMAGE=skillseraph:local ./test-gate.sh   # local image
#   ./test-gate.sh                            # uses ghcr.io default
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS="${NS:-default}"
IMAGE="${IMAGE:-ghcr.io/babywyrm/skillseraph:latest}"

cleanup() {
  kubectl delete pod agent-with-gate -n "$NS" --force --grace-period=0 2>/dev/null || true
  kubectl delete configmap agent-configs -n "$NS" --ignore-not-found 2>/dev/null || true
}
trap cleanup EXIT

echo "=== [1/4] Apply POISONED ConfigMap ==="
kubectl apply -n "$NS" -f "$HERE/configmap-poisoned.yaml"
kubectl create configmap agent-configs -n "$NS" \
  --from-literal=AGENTS.md="$(kubectl get configmap agent-configs-poisoned -n "$NS" -o jsonpath='{.data.AGENTS\.md}')" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -

echo "=== [2/4] Create gated pod (expect INIT FAILURE) ==="
sed "s|ghcr.io/babywyrm/skillseraph:latest|$IMAGE|" "$HERE/init-container-example.yaml" \
  | kubectl apply -n "$NS" -f -
sleep 10
STATUS=$(kubectl get pod agent-with-gate -n "$NS" -o jsonpath='{.status.initContainerStatuses[0].state.terminated.exitCode}' 2>/dev/null || echo "running")
if [ "$STATUS" != "0" ] && [ "$STATUS" != "running" ]; then
  echo "[PASS] Init container FAILED (exit $STATUS) — poisoned config blocked"
else
  echo "[FAIL] Init container did not fail (status=$STATUS)"
  kubectl logs agent-with-gate -n "$NS" -c skillseraph-gate 2>/dev/null | tail -5
  exit 1
fi

echo "=== [3/4] Switch to CLEAN ConfigMap ==="
kubectl delete pod agent-with-gate -n "$NS" --force --grace-period=0 2>/dev/null || true
kubectl apply -n "$NS" -f "$HERE/configmap-clean.yaml"
kubectl create configmap agent-configs -n "$NS" \
  --from-literal=AGENTS.md="$(kubectl get configmap agent-configs-clean -n "$NS" -o jsonpath='{.data.AGENTS\.md}')" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -

echo "=== [4/4] Create gated pod (expect SUCCESS) ==="
sed "s|ghcr.io/babywyrm/skillseraph:latest|$IMAGE|" "$HERE/init-container-example.yaml" \
  | kubectl apply -n "$NS" -f -
kubectl wait --for=condition=Ready pod/agent-with-gate -n "$NS" --timeout=60s
echo "[PASS] Pod started with clean configs"
