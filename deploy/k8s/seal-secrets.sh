#!/usr/bin/env bash
# Turn the two provisioner secrets into SealedSecrets you can commit.
# Needs: kubeseal, a cluster running the sealed-secrets controller.
#   ./seal-secrets.sh ~/.ssh/provisioner_ed25519 > overlays/prod/sealed-secrets.yaml
set -euo pipefail
KEY_FILE="${1:?usage: seal-secrets.sh <ssh-private-key-file> [token]}"
TOKEN="${2:-$(openssl rand -hex 32)}"
for c in kubectl kubeseal; do command -v "$c" >/dev/null || { echo "missing CLI: $c" >&2; exit 1; }; done
CTRL_ARGS=(--controller-name sealed-secrets-controller --controller-namespace kube-system)

kubectl -n provisioner create secret generic provisioner-api-token \
  --from-literal=PROVISIONER_API_TOKEN="$TOKEN" --dry-run=client -o yaml \
  | kubeseal "${CTRL_ARGS[@]}" --format yaml
echo "---"
kubectl -n provisioner create secret generic provisioner-ssh-key \
  --from-file=id_ed25519="$KEY_FILE" --dry-run=client -o yaml \
  | kubeseal "${CTRL_ARGS[@]}" --format yaml
echo "API token (keep it, it is not recoverable from the sealed file): $TOKEN" >&2
