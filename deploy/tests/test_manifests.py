"""Unit tests over the rendered Kustomize overlays. Run from anywhere:

    python3 -m unittest deploy/tests/test_manifests.py -v

Needs `kustomize` on PATH (and PyYAML; falls back to kustomize -o json)."""
import json
import os
import re
import subprocess
import unittest
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[1]
APP = DEPLOY.parent  # the project folder that holds deploy/ (repo root or a subfolder)
OVERLAYS = ["dev", "prod"]


def build(overlay):
    out = subprocess.run(["kustomize", "build", "-o", "/dev/stdout", str(DEPLOY / "k8s" / "overlays" / overlay)],
                         check=True, capture_output=True, text=True).stdout
    try:
        import yaml  # type: ignore
        return [d for d in yaml.safe_load_all(out) if d]
    except ImportError:  # pragma: no cover
        docs = []
        for chunk in out.split("\n---\n"):
            docs.append(json.loads(subprocess.run(["python3", "-c",
                "import sys,json,yaml;print(json.dumps(yaml.safe_load(sys.stdin)))"],
                input=chunk, capture_output=True, text=True, check=True).stdout))
        return docs


def one(docs, kind):
    found = [d for d in docs if d["kind"] == kind]
    assert len(found) == 1, "expected exactly one %s, got %d" % (kind, len(found))
    return found[0]


class DeploymentHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rendered = {o: build(o) for o in OVERLAYS}

    def deployments(self):
        for overlay, docs in self.rendered.items():
            with self.subTest(overlay=overlay):
                yield overlay, one(docs, "Deployment")

    def test_single_replica_recreate(self):
        for _, dep in self.deployments():
            self.assertEqual(dep["spec"]["replicas"], 1)
            self.assertEqual(dep["spec"]["strategy"]["type"], "Recreate")

    def test_probes_on_health_endpoint(self):
        for _, dep in self.deployments():
            c = dep["spec"]["template"]["spec"]["containers"][0]
            for probe in ("startupProbe", "readinessProbe", "livenessProbe"):
                self.assertIn(probe, c, probe)
                self.assertEqual(c[probe]["httpGet"]["path"], "/health", probe)

    def test_requests_and_limits(self):
        for _, dep in self.deployments():
            res = dep["spec"]["template"]["spec"]["containers"][0]["resources"]
            for key in ("cpu", "memory"):
                self.assertIn(key, res["requests"])
                self.assertIn(key, res["limits"])

    def test_non_root_and_hardened(self):
        for _, dep in self.deployments():
            pod = dep["spec"]["template"]["spec"]
            self.assertTrue(pod["securityContext"]["runAsNonRoot"])
            self.assertGreaterEqual(pod["securityContext"]["runAsUser"], 10000)
            self.assertEqual(pod["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
            c = pod["containers"][0]["securityContext"]
            self.assertFalse(c["allowPrivilegeEscalation"])
            self.assertTrue(c["readOnlyRootFilesystem"])
            self.assertEqual(c["capabilities"]["drop"], ["ALL"])
            self.assertFalse(pod.get("automountServiceAccountToken", True))

    def test_ssh_key_mounted_read_only_from_secret(self):
        for _, dep in self.deployments():
            pod = dep["spec"]["template"]["spec"]
            vol = next(v for v in pod["volumes"] if v["name"] == "ssh-key")
            self.assertEqual(vol["secret"]["secretName"], "provisioner-ssh-key")
            self.assertEqual(vol["secret"]["defaultMode"], 0o400)
            mount = next(m for m in pod["containers"][0]["volumeMounts"] if m["name"] == "ssh-key")
            self.assertTrue(mount["readOnly"])

    def test_data_dir_on_pvc(self):
        for overlay, docs in self.rendered.items():
            pvc = one(docs, "PersistentVolumeClaim")
            self.assertEqual(pvc["spec"]["resources"]["requests"]["storage"], "5Gi")
            if overlay == "prod":
                self.assertEqual(pvc["spec"]["storageClassName"], "gp3")
            cm = one(docs, "ConfigMap")
            self.assertEqual(cm["data"]["PROVISIONER_DATA_DIR"], "/data")

    def test_dev_is_dry_run_prod_is_not(self):
        self.assertEqual(one(self.rendered["dev"], "ConfigMap")["data"]["PROVISIONER_DRY_RUN"], "true")
        self.assertEqual(one(self.rendered["prod"], "ConfigMap")["data"]["PROVISIONER_DRY_RUN"], "false")

    def test_expected_kinds_present(self):
        for overlay, docs in self.rendered.items():
            kinds = sorted(d["kind"] for d in docs)
            self.assertEqual(kinds, ["ConfigMap", "Deployment", "Ingress", "Namespace", "NetworkPolicy",
                                     "PersistentVolumeClaim", "PodDisruptionBudget", "Service", "ServiceAccount"],
                             overlay)
            self.assertNotIn("Secret", kinds, "plain Secrets must never be part of the overlays")

    def test_ingress_has_tls(self):
        for _, docs in self.rendered.items():
            ing = one(docs, "Ingress")
            self.assertTrue(ing["spec"]["tls"])
            self.assertIn("cert-manager.io/cluster-issuer", ing["metadata"]["annotations"])

    def test_networkpolicy_restricts_both_directions(self):
        for _, docs in self.rendered.items():
            np = one(docs, "NetworkPolicy")
            self.assertEqual(sorted(np["spec"]["policyTypes"]), ["Egress", "Ingress"])


class NoRealSecretsInGit(unittest.TestCase):
    PLACEHOLDERS = {"REPLACE_ME", "", None}

    def tracked(self):
        out = subprocess.run(["git", "ls-files", "."], cwd=APP, capture_output=True,
                             text=True, check=True).stdout.split()
        files = [APP / p for p in out]
        assert files, "git ls-files returned nothing; is %s inside a git checkout?" % APP
        return files

    def test_secret_manifests_only_carry_placeholders(self):
        import yaml  # type: ignore
        for path in list((DEPLOY / "k8s").rglob("*.yaml")) + list((DEPLOY / "argocd").rglob("*.yaml")):
            for doc in yaml.safe_load_all(path.read_text()):
                if not doc or doc.get("kind") != "Secret":
                    continue
                for section in ("data", "stringData"):
                    for key, value in (doc.get(section) or {}).items():
                        self.assertIn(value, self.PLACEHOLDERS, "%s: %s has a non-placeholder value" % (path, key))

    def test_no_private_keys_or_aws_keys_tracked(self):
        pattern = re.compile(rb"BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY|AKIA[0-9A-Z]{16}")
        for path in self.tracked():
            if path.suffix in (".png", ".jpg") or not path.is_file() or path == Path(__file__):
                continue
            self.assertIsNone(pattern.search(path.read_bytes()), "possible secret in %s" % path)

    def test_forbidden_paths_not_tracked(self):
        bad = [p for p in self.tracked() if p.suffix == ".pem" or
               {"data", "venv", ".venv"} & set(p.relative_to(APP).parts[:-1])]
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
