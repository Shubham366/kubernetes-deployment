#!/usr/bin/env bash
# Install / upgrade the cluster components with Helm, using the pinned
# versions in components.env and the values files in values/.
#
#   ./install-components.sh                 # everything
#   ./install-components.sh ingress-nginx   # one component
#   SKIP_AWS=1 ./install-components.sh      # on kind: skip the EBS CSI driver
#   ACME_EMAIL=you@example.com ./install-components.sh cert-manager
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for c in helm kubectl; do command -v "$c" >/dev/null || { echo "missing CLI: $c" >&2; exit 1; }; done
kubectl cluster-info >/dev/null || { echo "no reachable cluster (check KUBECONFIG)" >&2; exit 1; }

ONLY=("$@")
want() { [ ${#ONLY[@]} -eq 0 ] || printf '%s\n' "${ONLY[@]}" | grep -qx "$1"; }

while IFS='|' read -r name repo url chart version ns; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  want "$name" || continue
  if [ "$name" = "aws-ebs-csi-driver" ] && [ "${SKIP_AWS:-0}" = "1" ]; then
    echo ">> skipping $name (SKIP_AWS=1)"; continue
  fi
  echo ">> $name ($chart $version) -> namespace $ns"
  if [ "$repo" = "oci" ]; then
    ref="$url/$chart"
  else
    helm repo add "$repo" "$url" --force-update >/dev/null
    helm repo update "$repo" >/dev/null
    ref="$repo/$chart"
  fi
  helm upgrade --install "$name" "$ref" \
    --version "$version" \
    --namespace "$ns" --create-namespace \
    --values "$HERE/values/$name.yaml" \
    --wait --timeout 10m
done < "$HERE/components.env"

# Post-install resources that depend on CRDs the charts created.
if want cert-manager; then
  echo ">> ClusterIssuers"
  ACME_EMAIL="${ACME_EMAIL:-admin@example.com}" envsubst < "$HERE/extras/cluster-issuers.yaml" | kubectl apply -f -
fi
if want aws-ebs-csi-driver && [ "${SKIP_AWS:-0}" != "1" ]; then
  echo ">> gp3 default StorageClass"
  kubectl apply -f "$HERE/extras/storageclass-gp3.yaml"
  # demote kOps' default so gp3 is the only default
  kubectl annotate storageclass kops-csi-1-21 storageclass.kubernetes.io/is-default-class- --overwrite 2>/dev/null || true
  kubectl annotate storageclass default storageclass.kubernetes.io/is-default-class- --overwrite 2>/dev/null || true
fi
echo ">> components installed:"
helm list -A
