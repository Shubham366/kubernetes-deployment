# Deploying the Linux provisioning backend to Kubernetes

Everything in this folder takes the Python backend in `linux-provision/` from
zero to a running, TLS-fronted API on a kOps cluster in AWS, installed by Helm
and kept in sync by Argo CD. Nothing here changes the application: the only file added outside `deploy/`
is the `Dockerfile`. The deploy layer depends on the container contract only
(image, port 8080, unauthenticated `GET /health`, `PROVISIONER_*` env
settings, data dir `/data`, SSH key at `/etc/provisioner/ssh/id_ed25519`).

```
deploy/
  kops/      create-cluster.sh, delete-cluster.sh, cluster.yaml, env.sh
  helm/      install-components.sh, components.env (pinned versions), values/, extras/
  k8s/       base/ (plain manifests) + overlays/dev + overlays/prod, seal-secrets.sh
  argocd/    install-argocd.sh, values.yaml, project.yaml, root-app.yaml, apps/
  tests/     static.sh (no cluster), test_manifests.py, live.sh (+ --kind), kind-config.yaml
```

## Cost warning

The kOps defaults create, in `ap-southeast-2`: 3 x `t3.medium` EC2 instances,
3 gp3 root volumes, 2 etcd volumes, 1 Network Load Balancer for the API
server, 1 NLB for ingress-nginx, EBS volumes for the app (5 Gi) and Prometheus
(10 Gi), and an S3 bucket. Expect roughly **US$0.20 to 0.30 per hour,
US$150 to 200 per month** if left running. Run
`deploy/kops/delete-cluster.sh` as soon as you are done, and check the AWS
console (EC2, EBS, Load Balancers, S3) afterwards.

## Prerequisites

| Tool | Why | macOS install |
|---|---|---|
| `aws` CLI with credentials | create the cluster | `brew install awscli` |
| `kops` | cluster lifecycle | `brew install kops` |
| `kubectl`, `kustomize`, `helm` | manifests and charts | `brew install kubectl kustomize helm` |
| `envsubst` (gettext) | render templates | `brew install gettext` |
| `kubeconform`, `shellcheck` | static tests | `brew install kubeconform shellcheck` |
| `docker`, `kind` | local live test | Docker Desktop, `brew install kind` |
| `kubeseal` | commit encrypted secrets | `brew install kubeseal` |
| Python 3.9+ with PyYAML | unit tests | `pip3 install pyyaml` |

IAM: the user running kOps needs EC2, Route53, S3, IAM, VPC, Autoscaling, SQS
and EventBridge permissions (the kOps docs list the exact policy).

## Step 0: tests that need no cluster

```bash
linux-provision/deploy/tests/static.sh
```

It builds the base and both overlays, validates every manifest with
kubeconform (CRD schemas from the datree catalog), renders the kOps template,
templates every Helm chart with its values file, shellchecks every script, runs
the unit tests in `tests/test_manifests.py` and scans git for private keys,
AWS keys, `.pem`, `data/` and `venv/`. It ends with `STATIC TIER: PASS`.

## Step 1: build and push the image

```bash
cd linux-provision
docker build -t ghcr.io/<you>/linux-provision:dev .
docker push ghcr.io/<you>/linux-provision:dev
```

Then change the image name in `k8s/base/deployment.yaml` and the tags in
`k8s/overlays/*/kustomization.yaml`. The image is `python:3.12-slim` plus
`ansible-core` and `openssh-client`, runs as uid 10001, and expects the data
dir at `/data` and the SSH key at `/etc/provisioner/ssh/id_ed25519`.

## Step 2: kOps cluster on AWS

```bash
cd linux-provision/deploy/kops
# optional overrides, see env.sh for all of them
export AWS_REGION=ap-southeast-2 KOPS_NODE_SIZE=t3.medium KOPS_NODE_COUNT=2
export KOPS_DNS_MODE=gossip KOPS_CLUSTER_NAME=provisioner.k8s.local
./create-cluster.sh
```

The script creates a versioned, encrypted S3 state bucket
(`kops-state-<account>-<region>`), renders `cluster.yaml` with `envsubst`,
creates or replaces the cluster spec, uploads your public SSH key, applies,
waits for `kops validate cluster` and prints the nodes. API server and SSH are
restricted to your current public IP (`KOPS_ADMIN_ACCESS`). For Route53 set
`KOPS_DNS_MODE=route53` and a cluster name under a hosted zone you own.

Verify:

```bash
kubectl get nodes -o wide      # 1 control-plane + 2 nodes, Ready
kops validate cluster
```

## Step 3: cluster components with Helm

```bash
cd linux-provision/deploy/helm
ACME_EMAIL=you@example.com ./install-components.sh
```

Pinned in `components.env`:

| Component | Chart | Namespace | Notes |
|---|---|---|---|
| ingress-nginx 4.12.1 | ingress-nginx | ingress-nginx | NLB, default IngressClass |
| cert-manager v1.17.1 | jetstack | cert-manager | plus 3 ClusterIssuers in `extras/` |
| metrics-server 3.12.2 | metrics-server | kube-system | `--kubelet-insecure-tls` |
| kube-prometheus-stack 69.8.2 | prometheus-community | monitoring | 3 d retention, 10 Gi gp3 |
| aws-ebs-csi-driver 2.41.0 | aws-ebs-csi-driver | kube-system | plus default `gp3` StorageClass |
| sealed-secrets 2.22.0 | OCI `registry-1.docker.io/bitnamicharts` | kube-system | see below |

Why Sealed Secrets rather than External Secrets: the app has exactly two
secrets (API token, SSH key). Sealed Secrets keeps them encrypted in git so
Argo CD can sync them, needs no AWS Secrets Manager, IAM role or extra
monthly cost, and works the same on kind. External Secrets is the right tool
once secrets are owned by an external store.

Verify:

```bash
helm list -A
kubectl get storageclass            # gp3 (default)
kubectl get clusterissuer           # selfsigned, letsencrypt-staging, letsencrypt-prod
kubectl -n ingress-nginx get svc    # EXTERNAL-IP of the NLB
kubectl top nodes                   # metrics-server works
```

## Step 4: the application

Create the two secrets out of band (never commit real values):

```bash
kubectl create namespace provisioner --dry-run=client -o yaml | kubectl apply -f -
kubectl -n provisioner create secret generic provisioner-api-token \
  --from-literal=PROVISIONER_API_TOKEN="$(openssl rand -hex 32)"
kubectl -n provisioner create secret generic provisioner-ssh-key \
  --from-file=id_ed25519=$HOME/.ssh/provisioner_ed25519
```

Or, for GitOps, seal them and commit the output into `k8s/overlays/prod/`:

```bash
linux-provision/deploy/k8s/seal-secrets.sh ~/.ssh/provisioner_ed25519 \
  > linux-provision/deploy/k8s/overlays/prod/sealed-secrets.yaml
```

Then apply an overlay:

```bash
kubectl apply -k linux-provision/deploy/k8s/overlays/dev    # dry-run mode
kubectl apply -k linux-provision/deploy/k8s/overlays/prod   # real Ansible runs
```

What the base contains: Namespace (restricted Pod Security), ServiceAccount
(no token automount), ConfigMap of `PROVISIONER_*` settings, PVC (gp3, 5 Gi),
Deployment (1 replica, `Recreate`, startup/readiness/liveness probes on
`/health`, requests and limits, non-root uid 10001, read-only root fs,
all capabilities dropped, SSH key mounted 0400), ClusterIP Service, Ingress
with cert-manager TLS, NetworkPolicy (ingress only from ingress-nginx and
monitoring, egress only DNS and SSH), PodDisruptionBudget.

Verify:

```bash
kubectl -n provisioner rollout status deploy/provisioner
kubectl -n provisioner port-forward svc/provisioner 18080:80 &
curl -s localhost:18080/health
curl -s -H "Authorization: Bearer $TOKEN" localhost:18080/api/v1/catalog | head
```

Point DNS for the Ingress host (`provisioner.example.com` in prod, edit
`overlays/prod/patch-ingress.yaml`) at the ingress-nginx NLB, then
`curl https://provisioner.example.com/health`.

## Step 5: Argo CD

```bash
cd linux-provision/deploy/argocd
REPO_URL=https://github.com/<you>/<repo>.git TARGET_REVISION=main ./install-argocd.sh
```

This installs the `argo/argo-cd` chart 7.8.13, the `linux-provision`
AppProject and the root app-of-apps, which watches `deploy/argocd/apps/` and
creates one Application per file: the six Helm components (multi-source, values
pulled from this repo), `cluster-extras` (issuers and StorageClass) and
`provisioner` (Kustomize overlay). Every Application has
`automated: {prune: true, selfHeal: true}` and sync waves so CRDs land before
the things that use them. Edit the `repoURL` fields in `apps/*.yaml` and
`project.yaml` to your fork.

Verify:

```bash
kubectl -n argocd port-forward svc/argocd-server 8443:443 &
# login: admin / password printed by the script
kubectl -n argocd get applications      # all Synced / Healthy
```

## Live tests (tier 2)

```bash
# local, needs Docker: creates kind cluster "provisioner", builds and loads the
# image, applies overlays/dev, creates throwaway secrets, checks health, auth,
# runs a dry-run job end to end, deletes the cluster (KEEP=1 to keep it)
linux-provision/deploy/tests/live.sh --kind

# against any cluster you already have
KUBECONFIG=~/.kube/config linux-provision/deploy/tests/live.sh
```

`live.sh` ends with `LIVE TIER: PASS`. On kind there is no ingress controller
or cert-manager unless you run `SKIP_AWS=1 deploy/helm/install-components.sh
ingress-nginx cert-manager` first; the test uses a port-forward so it does not
need them.

## Teardown

```bash
linux-provision/deploy/kops/delete-cluster.sh                   # cluster only
DELETE_STATE_BUCKET=1 linux-provision/deploy/kops/delete-cluster.sh
```

The script deletes the cluster through kOps (EC2, EBS, load balancers, VPC,
security groups, IAM roles), optionally empties and removes the versioned
state bucket, and prints any instance still tagged with the cluster name.
PVC-backed EBS volumes are deleted with the cluster because the StorageClass
uses `reclaimPolicy: Delete`; confirm in the EC2 console under Volumes.

## Later: hard features

1. **PostgreSQL instead of SQLite, so the API can scale past one replica.**
   Add a `Store` backend behind the same interface, run PostgreSQL as a
   StatefulSet (or CloudNativePG operator with streaming replication and a
   read-write Service), move job state and locks into the database with
   `SELECT ... FOR UPDATE SKIP LOCKED`, switch the Deployment to
   `RollingUpdate` with 3 replicas and a real PodDisruptionBudget. Hard parts:
   schema migration tooling, job ownership across replicas, cancelling a job
   that runs on another pod.
2. **Ansible jobs as Kubernetes Jobs behind a queue.** Replace the in-process
   thread pool with a producer that writes to a queue (Redis Streams or NATS
   JetStream) and a controller that turns each queued job into a Kubernetes
   `Job` running the same image with the SSH key mounted. Logs stream to the
   PVC or to Loki; the API pod becomes stateless and can be restarted mid-run
   without losing jobs. Hard parts: idempotent retries of half-applied
   playbooks, per-cluster patch locks across pods, log tailing while a Job is
   running, RBAC for the controller.
3. **Progressive delivery with Argo Rollouts and Prometheus analysis.** Turn
   the Deployment into a `Rollout` with a canary step (10 %, 50 %, 100 %)
   behind ingress-nginx traffic splitting, an `AnalysisTemplate` that queries
   the kube-prometheus-stack for 5xx ratio and p95 latency of
   `/health` and job failure rate, automatic rollback on failure, and
   Argo CD notifications to Slack. Hard parts: this needs feature 1 first
   (two versions sharing one SQLite file is not safe), metrics the app does not
   expose yet, and a load generator so the analysis has data.
