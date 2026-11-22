#!/usr/bin/env bash
# Tear the kOps cluster down and (optionally) the state bucket.
#   ./delete-cluster.sh                # deletes the cluster, keeps the bucket
#   DELETE_STATE_BUCKET=1 ./delete-cluster.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$HERE/env.sh"

require_cli kops aws
resolve_state_store

if kops get cluster --name "$KOPS_CLUSTER_NAME" >/dev/null 2>&1; then
  echo ">> deleting cluster $KOPS_CLUSTER_NAME (this removes EC2, EBS, ELB, VPC)"
  kops delete cluster --name "$KOPS_CLUSTER_NAME" --yes
else
  echo ">> cluster $KOPS_CLUSTER_NAME not found in $KOPS_STATE_STORE, nothing to delete"
fi

if [ "${DELETE_STATE_BUCKET:-0}" = "1" ]; then
  if aws s3api head-bucket --bucket "$KOPS_STATE_BUCKET" 2>/dev/null; then
    echo ">> emptying and deleting bucket $KOPS_STATE_BUCKET"
    aws s3 rm "s3://$KOPS_STATE_BUCKET" --recursive
    # versioned bucket: delete all versions and markers
    aws s3api list-object-versions --bucket "$KOPS_STATE_BUCKET" \
      --query '{Objects: [Versions[].{Key:Key,VersionId:VersionId}, DeleteMarkers[].{Key:Key,VersionId:VersionId}][]}' \
      --output json > /tmp/kops-versions.json
    if grep -q '"Key"' /tmp/kops-versions.json; then
      aws s3api delete-objects --bucket "$KOPS_STATE_BUCKET" --delete file:///tmp/kops-versions.json >/dev/null
    fi
    aws s3api delete-bucket --bucket "$KOPS_STATE_BUCKET"
  fi
fi

echo ">> leftover check (should be empty):"
aws ec2 describe-instances --region "$AWS_REGION" \
  --filters "Name=tag:KubernetesCluster,Values=$KOPS_CLUSTER_NAME" "Name=instance-state-name,Values=running,pending" \
  --query 'Reservations[].Instances[].InstanceId' --output text
