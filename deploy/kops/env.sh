#!/usr/bin/env bash
# Shared settings for the kOps scripts. Override any of these in your shell.
# Every value here is a plain variable, nothing is secret.

export AWS_REGION="${AWS_REGION:-ap-southeast-2}"
export AWS_PROFILE="${AWS_PROFILE:-}"

# gossip  -> cluster name must end in .k8s.local, no Route53 needed
# route53 -> cluster name must be a subdomain of a hosted zone you own
export KOPS_DNS_MODE="${KOPS_DNS_MODE:-gossip}"
export KOPS_CLUSTER_NAME="${KOPS_CLUSTER_NAME:-provisioner.k8s.local}"

# S3 bucket holding kOps state. Bucket names are global, so default to a
# name derived from the AWS account id (filled in by the scripts).
export KOPS_STATE_BUCKET="${KOPS_STATE_BUCKET:-}"
export KOPS_STATE_STORE="${KOPS_STATE_STORE:-}"

export KOPS_K8S_VERSION="${KOPS_K8S_VERSION:-1.31.5}"
export KOPS_ZONES="${KOPS_ZONES:-${AWS_REGION}a}"
export KOPS_NETWORK_CIDR="${KOPS_NETWORK_CIDR:-10.42.0.0/16}"

export KOPS_CONTROL_PLANE_SIZE="${KOPS_CONTROL_PLANE_SIZE:-t3.medium}"
export KOPS_CONTROL_PLANE_COUNT="${KOPS_CONTROL_PLANE_COUNT:-1}"
export KOPS_NODE_SIZE="${KOPS_NODE_SIZE:-t3.medium}"
export KOPS_NODE_COUNT="${KOPS_NODE_COUNT:-2}"
export KOPS_NODE_VOLUME_GB="${KOPS_NODE_VOLUME_GB:-40}"

# Public SSH key that kOps installs on every node (never the private key).
export KOPS_SSH_PUBLIC_KEY="${KOPS_SSH_PUBLIC_KEY:-$HOME/.ssh/id_ed25519.pub}"

# Restrict API server and SSH to these CIDRs (default: your current public IP).
export KOPS_ADMIN_ACCESS="${KOPS_ADMIN_ACCESS:-}"

require_cli() {
  local missing=0
  for c in "$@"; do
    if ! command -v "$c" >/dev/null 2>&1; then
      echo "missing CLI: $c" >&2
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
}

resolve_state_store() {
  if [ -z "$KOPS_STATE_BUCKET" ]; then
    local account
    account="$(aws sts get-caller-identity --query Account --output text)"
    KOPS_STATE_BUCKET="kops-state-${account}-${AWS_REGION}"
  fi
  KOPS_STATE_STORE="s3://${KOPS_STATE_BUCKET}"
  export KOPS_STATE_BUCKET KOPS_STATE_STORE
}
