#!/usr/bin/env bash
# Install Argo CD with Helm and bootstrap the app-of-apps.
#   ./install-argocd.sh                         # install + root app
#   REPO_URL=https://github.com/you/repo.git TARGET_REVISION=main ./install-argocd.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for c in helm kubectl envsubst; do command -v "$c" >/dev/null || { echo "missing CLI: $c" >&2; exit 1; }; done
kubectl cluster-info >/dev/null || { echo "no reachable cluster (check KUBECONFIG)" >&2; exit 1; }

ARGOCD_CHART_VERSION="${ARGOCD_CHART_VERSION:-7.8.13}"   # Argo CD v2.14.x
export REPO_URL="${REPO_URL:-https://github.com/ORG/REPO.git}"
export TARGET_REVISION="${TARGET_REVISION:-main}"
export REPO_PATH_PREFIX="${REPO_PATH_PREFIX:-linux-provision/deploy}"
export APP_ENV="${APP_ENV:-dev}"

helm repo add argo https://argoproj.github.io/argo-helm --force-update >/dev/null
helm repo update argo >/dev/null
helm upgrade --install argocd argo/argo-cd \
  --version "$ARGOCD_CHART_VERSION" \
  --namespace argocd --create-namespace \
  --values "$HERE/values.yaml" \
  --wait --timeout 10m

echo ">> AppProject + root application"
kubectl apply -f "$HERE/project.yaml"
envsubst < "$HERE/root-app.yaml" | kubectl apply -f -

echo ">> initial admin password (not printed here; run this yourself):"
echo "   kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
echo ">> UI: kubectl -n argocd port-forward svc/argocd-server 8443:443  ->  https://localhost:8443"
