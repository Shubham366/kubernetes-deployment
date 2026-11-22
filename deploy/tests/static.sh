#!/usr/bin/env bash
# Tier 1: no cluster and no git checkout needed (works from a plain copy of the folder). Validates every manifest, builds both overlays,
# templates every Helm values file, shellchecks the scripts, runs the unit tests.
#   deploy/tests/static.sh
# Needs: kubectl, kustomize, helm, kubeconform (or falls back to kubectl
# --dry-run=client when kubeconform is missing), shellcheck, python3.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY="$(cd "$HERE/.." && pwd)"
fail=0
step() { printf '\n== %s\n' "$*"; }
need() { command -v "$1" >/dev/null || { echo "missing CLI: $1" >&2; exit 1; }; }
need kubectl; need kustomize; need helm; need python3; need envsubst

CRD_SCHEMAS='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
validate() { # file-or-stream description
  if command -v kubeconform >/dev/null; then
    kubeconform -strict -summary -ignore-missing-schemas \
      -schema-location default -schema-location "$CRD_SCHEMAS" \
      -skip SealedSecret "$@"
  else
    echo "(kubeconform missing: using kubectl --dry-run=client, CRD kinds are skipped)"
    kubectl apply --dry-run=client --validate=strict -f "$@" -o name
  fi
}

step "kustomize build: base, overlays/dev, overlays/prod"
for d in base overlays/dev overlays/prod; do
  out="$(mktemp).yaml"; kustomize build "$DEPLOY/k8s/$d" > "$out"
  echo "  $d: $(grep -c '^kind:' "$out") resources"
  validate "$out" || fail=1
  rm -f "$out"
done

step "validate plain manifests (examples, helm extras, argocd)"
validate "$DEPLOY"/k8s/base/secret-*.example.yaml || fail=1
validate "$DEPLOY"/helm/extras/storageclass-gp3.yaml || fail=1
ACME_EMAIL=test@example.com envsubst < "$DEPLOY/helm/extras/cluster-issuers.yaml" | validate - || fail=1
validate "$DEPLOY"/argocd/project.yaml "$DEPLOY"/argocd/apps/*.yaml || fail=1
REPO_URL=https://example.com/r.git TARGET_REVISION=main REPO_PATH_PREFIX=linux-provision/deploy \
  envsubst < "$DEPLOY/argocd/root-app.yaml" | validate - || fail=1

step "kops cluster template renders and parses"
( set -a; source "$DEPLOY/kops/env.sh"; KOPS_STATE_STORE=s3://example KOPS_ADMIN_ACCESS=203.0.113.1/32 \
  envsubst < "$DEPLOY/kops/cluster.yaml" | python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
kinds = [d["kind"] for d in docs]
assert kinds == ["Cluster", "InstanceGroup", "InstanceGroup"], kinds
print("  kinds:", kinds)' ) || fail=1

step "helm template with every values file"
while IFS='|' read -r name repo url chart version ns; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  if [ "$repo" = "oci" ]; then ref="$url/$chart"; else
    helm repo add "$repo" "$url" --force-update >/dev/null 2>&1 || { echo "  $name: helm repo add failed"; fail=1; continue; }
    ref="$repo/$chart"; fi
  printf '  %-24s %s %s ... ' "$name" "$chart" "$version"
  out="$(mktemp)"
  if helm template "$name" "$ref" --version "$version" --namespace "$ns" \
       --values "$DEPLOY/helm/values/$name.yaml" --include-crds > "$out" 2>"$out.err"; then
    echo "$(grep -c '^kind:' "$out") resources"
  else
    echo FAILED; cat "$out.err"; fail=1
  fi
  rm -f "$out" "$out.err"
done < "$DEPLOY/helm/components.env"
helm repo add argo https://argoproj.github.io/argo-helm --force-update >/dev/null 2>&1
printf '  %-24s argo-cd ... ' argocd
helm template argocd argo/argo-cd --version 7.8.13 --namespace argocd \
  --values "$DEPLOY/argocd/values.yaml" > /dev/null && echo ok || fail=1

step "shellcheck"
if command -v shellcheck >/dev/null; then
  shellcheck -x -S warning "$DEPLOY"/kops/*.sh "$DEPLOY"/helm/*.sh "$DEPLOY"/k8s/*.sh \
    "$DEPLOY"/argocd/*.sh "$DEPLOY"/tests/*.sh && echo "  ok"
else
  echo "  shellcheck missing, skipped"; fail=1
fi

step "python unit tests"
python3 -m unittest discover -s "$HERE" -p 'test_*.py' -v 2>&1 | tail -n 15
[ "${PIPESTATUS[0]}" -eq 0 ] || fail=1

step "secret / junk scan of the project tree (no git needed)"
APP_ROOT="$(cd "$DEPLOY/.." && pwd)"
cd "$APP_ROOT"
# a real virtualenv (has pyvenv.cfg) is the reviewer's own and is skipped
if find . \( -path ./.git -o -path '*/venv' -o -path '*/.venv' \) -prune -o \
     \( -name '*.pem' -o -path '*/data/*' \) -print | grep .; then
  echo "  forbidden files present"; fail=1
fi
for v in venv .venv; do
  if [ -d "$v" ] && [ ! -f "$v/pyvenv.cfg" ]; then echo "  $v/ is shipped in the tree"; fail=1; fi
done
if grep -rnE --exclude-dir=.git --exclude-dir=tests --exclude-dir=venv --exclude-dir=.venv --exclude='*.md' \
     'BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}' .; then
  echo "  possible real secret in the tree"; fail=1
fi
[ $fail -eq 0 ] && echo "  clean"

echo
[ $fail -eq 0 ] && echo "STATIC TIER: PASS" || { echo "STATIC TIER: FAIL"; exit 1; }
