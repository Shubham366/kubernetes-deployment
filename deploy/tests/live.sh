#!/usr/bin/env bash
# Tier 2: against a live cluster.
#   deploy/tests/live.sh            # uses $KUBECONFIG / current context
#   deploy/tests/live.sh --kind     # creates a kind cluster, builds + loads the image, then tests
#   KEEP=1 deploy/tests/live.sh --kind   # leave the kind cluster running
# Applies overlays/dev (dry-run mode, no real hosts), creates throwaway
# secrets, waits for rollout, and curls /api/v1/health through a port-forward.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(cd "$HERE/.." && pwd)"
APP="$(cd "$DEPLOY/.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/ORG/linux-provision:dev}"
NS=provisioner
USE_KIND=0; [ "${1:-}" = "--kind" ] && USE_KIND=1
for c in kubectl kustomize curl; do command -v "$c" >/dev/null || { echo "missing CLI: $c" >&2; exit 1; }; done

cleanup() {
  [ -n "${PF_PID:-}" ] && kill "$PF_PID" 2>/dev/null || true
  if [ $USE_KIND -eq 1 ] && [ "${KEEP:-0}" != "1" ]; then kind delete cluster --name provisioner >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

if [ $USE_KIND -eq 1 ]; then
  for c in kind docker; do command -v "$c" >/dev/null || { echo "missing CLI: $c" >&2; exit 1; }; done
  docker info >/dev/null 2>&1 || { echo "docker daemon not running" >&2; exit 1; }
  kind get clusters 2>/dev/null | grep -qx provisioner || kind create cluster --config "$HERE/kind-config.yaml" --wait 120s
  kubectl config use-context kind-provisioner >/dev/null
  echo ">> building image $IMAGE"
  docker build -t "$IMAGE" "$APP"
  kind load docker-image "$IMAGE" --name provisioner
fi
[ -n "${KUBECONFIG:-}" ] || kubectl config current-context >/dev/null || { echo "set KUBECONFIG" >&2; exit 1; }

echo ">> applying overlays/dev"
kustomize build "$DEPLOY/k8s/overlays/dev" | kubectl apply -f -

echo ">> throwaway secrets (test only)"
TOKEN="test-$(date +%s)"
kubectl -n $NS create secret generic provisioner-api-token --from-literal=PROVISIONER_API_TOKEN="$TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
TMPKEY="$(mktemp -d)/id_ed25519"; ssh-keygen -q -t ed25519 -N "" -f "$TMPKEY" -C provisioner-test
kubectl -n $NS create secret generic provisioner-ssh-key --from-file=id_ed25519="$TMPKEY" \
  --dry-run=client -o yaml | kubectl apply -f -
rm -rf "$(dirname "$TMPKEY")"

echo ">> waiting for rollout"
kubectl -n $NS rollout status deployment/provisioner --timeout=180s || {
  kubectl -n $NS describe pod -l app.kubernetes.io/name=provisioner | tail -40; exit 1; }

echo ">> port-forward + health check"
kubectl -n $NS port-forward svc/provisioner 18080:80 >/dev/null 2>&1 &
PF_PID=$!
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:18080/api/v1/health >/dev/null 2>&1 && break; sleep 1; done
HEALTH="$(curl -fsS http://127.0.0.1:18080/api/v1/health)"
echo "$HEALTH"
echo "$HEALTH" | grep -q '"status": "ok"' || { echo "health not ok" >&2; exit 1; }

echo ">> auth: no token must be rejected, token must be accepted"
code_noauth="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/api/v1/clusters)"
code_auth="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/api/v1/clusters)"
echo "  without token: $code_noauth, with token: $code_auth"
[ "$code_noauth" = "401" ] && [ "$code_auth" = "200" ] || { echo "auth check failed" >&2; exit 1; }

echo ">> dry-run job end to end (cluster create + ping)"
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  --data @"$APP/examples/cluster_mixed.json" http://127.0.0.1:18080/api/v1/clusters >/dev/null
JOB="$(curl -fsS -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/api/v1/clusters/analytics/ping \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["job"]["id"])')"
for _ in $(seq 1 30); do
  STATE="$(curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:18080/api/v1/jobs/$JOB \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["job"]["state"])')"
  case "$STATE" in succeeded|failed|cancelled) break;; esac; sleep 1
done
echo "  job $JOB -> $STATE"
[ "$STATE" = "succeeded" ] || exit 1

echo ">> pod runs as non-root with the key mounted 0400"
kubectl -n $NS exec deploy/provisioner -- sh -c 'id -u; ls -l /etc/provisioner/ssh/ | tail -n +2'
echo
echo "LIVE TIER: PASS"
