#!/usr/bin/env bash
# Create (or update) a kOps cluster on AWS for the provisioner.
# Idempotent: re-running updates the cluster spec instead of failing.
#
#   ./create-cluster.sh            # gossip DNS, ap-southeast-2, 1 CP + 2 nodes
#   KOPS_DNS_MODE=route53 KOPS_CLUSTER_NAME=k8s.example.com ./create-cluster.sh
#
# Costs money: 3 x t3.medium + EBS + NAT-less public topology, roughly
# US$0.20/hour. Run ./delete-cluster.sh when done.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

require_cli kops kubectl aws envsubst
resolve_state_store

case "$KOPS_DNS_MODE" in
  gossip)
    [[ "$KOPS_CLUSTER_NAME" == *.k8s.local ]] || {
      echo "gossip mode needs a cluster name ending in .k8s.local (got $KOPS_CLUSTER_NAME)" >&2; exit 1; } ;;
  route53)
    [[ "$KOPS_CLUSTER_NAME" != *.k8s.local ]] || {
      echo "route53 mode needs a real DNS name under a hosted zone you own" >&2; exit 1; } ;;
  *) echo "KOPS_DNS_MODE must be gossip or route53" >&2; exit 1 ;;
esac

[ -f "$KOPS_SSH_PUBLIC_KEY" ] || { echo "public key not found: $KOPS_SSH_PUBLIC_KEY" >&2; exit 1; }

if [ -z "$KOPS_ADMIN_ACCESS" ]; then
  KOPS_ADMIN_ACCESS="$(curl -fsS https://checkip.amazonaws.com)/32"
fi
export KOPS_ADMIN_ACCESS

echo ">> state store: $KOPS_STATE_STORE"
if ! aws s3api head-bucket --bucket "$KOPS_STATE_BUCKET" 2>/dev/null; then
  echo ">> creating state bucket $KOPS_STATE_BUCKET"
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$KOPS_STATE_BUCKET" --region "$AWS_REGION"
  else
    aws s3api create-bucket --bucket "$KOPS_STATE_BUCKET" --region "$AWS_REGION" \
      --create-bucket-configuration LocationConstraint="$AWS_REGION"
  fi
  aws s3api put-bucket-versioning --bucket "$KOPS_STATE_BUCKET" --versioning-configuration Status=Enabled
  aws s3api put-bucket-encryption --bucket "$KOPS_STATE_BUCKET" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  aws s3api put-public-access-block --bucket "$KOPS_STATE_BUCKET" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

RENDERED="$(mktemp)"
trap 'rm -f "$RENDERED"' EXIT
envsubst < "$HERE/cluster.yaml" > "$RENDERED"

if kops get cluster --name "$KOPS_CLUSTER_NAME" >/dev/null 2>&1; then
  echo ">> cluster exists, replacing spec"
  kops replace -f "$RENDERED" --force
else
  echo ">> creating cluster spec"
  kops create -f "$RENDERED"
fi

kops create sshpublickey --name "$KOPS_CLUSTER_NAME" -i "$KOPS_SSH_PUBLIC_KEY" 2>/dev/null \
  || kops create sshpublickey --name "$KOPS_CLUSTER_NAME" -i "$KOPS_SSH_PUBLIC_KEY" --force 2>/dev/null \
  || true

echo ">> applying"
kops update cluster --name "$KOPS_CLUSTER_NAME" --yes --admin

if kops rolling-update cluster --name "$KOPS_CLUSTER_NAME" 2>/dev/null | grep -q NeedsUpdate; then
  echo ">> rolling update needed"
  kops rolling-update cluster --name "$KOPS_CLUSTER_NAME" --yes
fi

echo ">> waiting for the cluster to validate (up to 15 min)"
kops validate cluster --name "$KOPS_CLUSTER_NAME" --wait 15m

kubectl get nodes -o wide
echo ">> done. kubeconfig context: $KOPS_CLUSTER_NAME"
