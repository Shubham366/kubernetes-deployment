# deploy/k8s

Plain manifests for the provisioner, assembled with Kustomize.

| Path | Purpose |
|---|---|
| `base/` | Namespace, ServiceAccount, ConfigMap, PVC (gp3, 5Gi), Deployment (1 replica, Recreate), Service, Ingress (TLS), NetworkPolicy, PDB |
| `base/secret-*.example.yaml` | Templates only. Never commit real values. |
| `overlays/dev` | dry-run mode, debug logs, small resources, `standard` StorageClass for kind |
| `overlays/prod` | letsencrypt-prod issuer, pinned image tag, place for SealedSecrets |
| `seal-secrets.sh` | produce SealedSecrets for git |

```bash
kustomize build overlays/dev
kubectl apply -k overlays/dev
```
