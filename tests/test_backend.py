"""End-to-end tests of the backend in dry-run mode (Ansible is never started).

Run with:  python -m unittest discover -s tests -v
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from provisioner.api.server import ApiServer
from provisioner.app import Application
from provisioner.catalog import auto_assign_roles, resolve_install_method, validate_topology
from provisioner.config import load_settings
from provisioner.controllers.patch_controller import parse_batch_size, tier_of
from provisioner.controllers.scan_controller import summarize_report
from provisioner.exceptions import ConflictError, NotFoundError, ValidationError
from provisioner.executor import parse_recap
from provisioner.models import Node, mask_secrets

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def example(name):
    return json.loads((EXAMPLES / name).read_text())


def node(hostname, os_type="ubuntu", os_version="22.04", roles=None):
    return Node(hostname=hostname, address=hostname, os_type=os_type, os_version=os_version, roles=roles or [])


class BackendCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="provisioner-test-")
        self.app = Application(load_settings(data_dir=self.tmp, dry_run=True, log_level="ERROR"))
        self.app.clusters.create(example("cluster_mixed.json"))

    def tearDown(self):
        self.app.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def wait(self, job):
        return self.app.jobs.wait(job.id, timeout=30)


class PureFunctionTests(unittest.TestCase):
    def test_parse_recap(self):
        lines = [
            "PLAY RECAP *****\n",
            "n1 : ok=5 changed=2 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0\n",
            "n2 : ok=1 changed=0 unreachable=1 failed=0\n",
            "n3.example.com            : ok=3    changed=0    unreachable=0    failed=2    skipped=0\n",
        ]
        recap = parse_recap(lines)
        self.assertEqual(recap["n1"]["changed"], 2)
        self.assertEqual(recap["n2"]["unreachable"], 1)
        self.assertEqual(recap["n3.example.com"]["failed"], 2)

    def test_mask_secrets(self):
        masked = mask_secrets({"redis_password": "x", "nested": {"api_token": "y", "port": 1}, "empty_password": ""})
        self.assertEqual(masked["redis_password"], "***")
        self.assertEqual(masked["nested"], {"api_token": "***", "port": 1})
        self.assertEqual(masked["empty_password"], "")

    def test_java_method_depends_on_os(self):
        self.assertEqual(resolve_install_method("java", "17", node("a"))[0], "package")
        self.assertEqual(resolve_install_method("java", "21", node("b", "centos", "7.9"))[0], "tarball")
        with self.assertRaises(ValidationError):
            resolve_install_method("java", "21", node("b", "centos", "7.9"), requested="package")

    def test_nodejs_rejected_on_el7(self):
        with self.assertRaises(ValidationError):
            resolve_install_method("nodejs", "20", node("c", "centos", "7.9"))
        self.assertEqual(resolve_install_method("nodejs", "16", node("c", "centos", "7.9"))[0], "tarball")

    def test_hadoop_ha_topology(self):
        nodes = [node("n%d" % i) for i in range(1, 6)]
        layout = auto_assign_roles("hadoop", "ha", nodes, {})
        assignment = {r: [n for n in nodes if n.hostname in hosts] for r, hosts in layout.items()}
        validate_topology("hadoop", "ha", "3.3.6", assignment, {"hadoop_replication_factor": 3})
        assignment["hadoop_journalnode"] = assignment["hadoop_journalnode"][:2]
        with self.assertRaises(ValidationError):
            validate_topology("hadoop", "ha", "3.3.6", assignment, {})

    def test_replication_factor_cannot_exceed_datanodes(self):
        nodes = [node("n1"), node("n2")]
        assignment = {"hadoop_namenode": [nodes[0]], "hadoop_resourcemanager": [nodes[0]],
                      "hadoop_datanode": [nodes[1]]}
        with self.assertRaises(ValidationError):
            validate_topology("hadoop", "standard", "3.3.6", assignment, {"hadoop_replication_factor": 3})

    def test_redis_cluster_needs_six_nodes(self):
        nodes = [node("n%d" % i) for i in range(1, 6)]
        with self.assertRaises(ValidationError):
            validate_topology("redis", "cluster", "7.2.5", {"redis_cluster": nodes}, {"redis_cluster_replicas": 1})

    def test_postgres_16_rejected_on_el7(self):
        with self.assertRaises(ValidationError):
            validate_topology("postgresql", "standalone", "16",
                              {"postgresql_primary": [node("p", "centos", "7.9")]}, {})

    def test_risk_score(self):
        clean = summarize_report({"packages": {}, "pending_updates": [], "compliance": []})
        self.assertEqual(clean["risk_score"], 0)
        risky = summarize_report({
            "packages": {"updates_available": 3, "security_updates": 2},
            "pending_updates": [{"name": "openssl", "security": True, "severity": "critical"},
                                {"name": "bash", "security": True, "severity": "low"}, {"name": "vim"}],
            "compliance": [{"id": "SSH-001", "status": "fail", "severity": "high"}],
            "reboot_required": True,
        })
        self.assertEqual(risky["security_updates"], 2)
        self.assertEqual(risky["risk_score"], 10 + 1 + 1 + 6 + 5)

    def test_batch_size(self):
        self.assertEqual(parse_batch_size("25%"), "25%")
        self.assertEqual(parse_batch_size("3"), 3)
        for bad in ("0", "-1", "abc", "150%"):
            with self.assertRaises(ValidationError):
                parse_batch_size(bad)

    def test_tiers(self):
        self.assertEqual(tier_of(node("a")), 0)
        self.assertEqual(tier_of(node("a", roles=["hadoop_datanode"])), 1)
        self.assertEqual(tier_of(node("a", roles=["hadoop_datanode", "postgresql_primary"])), 2)


class ClusterTests(BackendCase):
    def test_create_and_show(self):
        cluster = self.app.clusters.get("analytics")
        self.assertEqual(cluster["node_count"], 10)
        self.assertEqual(cluster["os_breakdown"], {"ubuntu": 5, "rhel": 3, "centos": 2})

    def test_duplicates_rejected(self):
        with self.assertRaises(ConflictError):
            self.app.clusters.create(example("cluster_mixed.json"))
        with self.assertRaises(ValidationError):
            self.app.clusters.create({"name": "dup", "nodes": [
                {"hostname": "a", "address": "10.0.0.1"}, {"hostname": "b", "address": "10.0.0.1"}]})

    def test_bad_input(self):
        for spec in ({"name": "1bad"}, {"name": "ok", "nodes": [{"hostname": "a", "os_type": "windows"}]},
                     {"name": "ok", "nodes": [{"hostname": "bad host"}]}):
            with self.assertRaises(ValidationError):
                self.app.clusters.create(spec)

    def test_inventory_groups(self):
        self.app.clusters.set_roles("analytics", {"redis_master": ["an-db-01"]})
        cluster = self.app.store.get_cluster("analytics")
        inventory = self.app.inventory.build(cluster)["all"]
        self.assertEqual(sorted(inventory["children"]["redis_master"]["hosts"]), ["an-db-01"])
        self.assertEqual(len(inventory["children"]["os_rhel"]["hosts"]), 3)
        self.assertIn("label_rack_r1", inventory["children"])
        self.assertEqual(inventory["hosts"]["an-worker-04"]["ansible_python_interpreter"], "auto_legacy_silent")

    def test_dry_run_ping_does_not_change_node_state(self):
        job = self.wait(self.app.clusters.ping("analytics"))
        self.assertEqual(job.status, "success")
        self.assertTrue(job.dry_run)
        states = {n["state"] for n in self.app.clusters.get("analytics")["nodes"]}
        self.assertEqual(states, {"registered"})

    def test_remove_node_with_roles_needs_force(self):
        self.app.clusters.set_roles("analytics", {"redis_master": ["an-db-01"]})
        with self.assertRaises(ConflictError):
            self.app.clusters.remove_node("analytics", "an-db-01")
        self.app.clusters.remove_node("analytics", "an-db-01", force=True)
        self.assertEqual(self.app.clusters.get("analytics")["node_count"], 9)


class VersionTests(BackendCase):
    def test_install_splits_steps_by_method(self):
        job = self.wait(self.app.versions.install("analytics", {"technology": "java", "version": "21"}))
        self.assertEqual(job.status, "success")
        methods = job.params["methods"]
        self.assertEqual(methods["tarball"], ["an-worker-04"])  # CentOS 7 has no JDK 21 package
        self.assertEqual(len(methods["package"]), 9)
        self.assertEqual(len(job.steps), 2)
        # dry run: nothing recorded as installed
        self.assertEqual(self.app.versions.list_installed("analytics"), [])

    def test_unknown_version_and_technology(self):
        with self.assertRaises(ValidationError):
            self.app.versions.install("analytics", {"technology": "java", "version": "99"})
        with self.assertRaises(ValidationError):
            self.app.versions.install("analytics", {"technology": "cobol"})
        with self.assertRaises(ValidationError):
            self.app.versions.install("analytics", {"technology": "java", "options": {"hadoop_version": "1"}})

    def test_impossible_combination_fails_before_any_step(self):
        with self.assertRaises(ValidationError):
            self.app.versions.install("analytics", {"technology": "nodejs", "version": "20"})
        self.assertEqual(self.app.store.list_jobs(), [])


class SoftwareTests(BackendCase):
    def test_hadoop_ha_plan_and_dry_run_deploy(self):
        plan = self.app.software.plan("analytics", "hadoop", example("hadoop_ha.json"))
        self.assertTrue(plan["vars"]["hadoop_ha_enabled"])
        self.assertEqual(plan["prerequisites"], ["java 11"])
        job = self.wait(self.app.software.deploy("analytics", "hadoop", example("hadoop_ha.json")))
        self.assertEqual(job.status, "success")
        self.assertEqual(job.steps[-1]["playbook"], "software/hadoop.yml")
        self.assertTrue(job.steps[0]["playbook"].startswith("versions/java"))
        # dry run must not persist roles or an installation record
        self.assertTrue(all(not n["roles"] for n in self.app.clusters.get("analytics")["nodes"]))
        self.assertEqual(self.app.software.list_deployed("analytics"), [])
        # ...but the simulated inventory did contain the role groups
        inventory = json.loads((Path(self.tmp) / "inventories" / ("analytics-%s.json" % job.id)).read_text())
        self.assertEqual(sorted(inventory["all"]["children"]["hadoop_journalnode"]["hosts"]),
                         ["an-master-01", "an-master-02", "an-master-03"])

    def test_passwords_generated_and_masked(self):
        plan = self.app.software.plan("analytics", "postgresql", example("postgresql_replication.json"))
        self.assertEqual(plan["vars"]["postgresql_replication_password"], "***")
        job = self.wait(self.app.software.deploy("analytics", "redis", example("redis_sentinel.json")))
        self.assertEqual(job.params["vars"]["redis_password"], "***")
        self.assertNotIn("redis_password\": \"***", "")  # sanity
        log = self.app.jobs.read_log(job.id)
        self.assertIn('"redis_password": "***"', log)

    def test_invalid_requests(self):
        with self.assertRaises(ValidationError):
            self.app.software.deploy("analytics", "mongodb", {})
        with self.assertRaises(ValidationError):
            self.app.software.deploy("analytics", "redis", {"mode": "cluster", "nodes": ["an-db-01", "an-db-02"]})
        with self.assertRaises(ValidationError):
            self.app.software.deploy("analytics", "redis", {"vars": {"redis_action": "uninstall"}})
        with self.assertRaises(NotFoundError):
            self.app.software.action("analytics", "redis", "restart")
        with self.assertRaises(ValidationError):
            self.app.software.action("analytics", "redis", "decommission")

    def test_auto_layout(self):
        plan = self.app.software.plan("analytics", "postgresql",
                                      {"mode": "replication", "version": "15",
                                       "nodes": ["an-db-01", "an-db-02", "an-db-03"]})
        self.assertEqual(plan["roles"], {"postgresql_primary": ["an-db-01"],
                                         "postgresql_replica": ["an-db-02", "an-db-03"]})


class ScanAndPatchTests(BackendCase):
    def test_dry_run_scan_is_flagged_simulated(self):
        job = self.wait(self.app.scans.run("analytics", {"scan_type": "vulnerability"}))
        self.assertEqual(job.status, "success")
        self.assertTrue(job.result["simulated"])
        hosts = self.app.scans.get(job.id)["hosts"]
        self.assertEqual(len(hosts), 10)
        self.assertEqual({h["status"] for h in hosts}, {"simulated"})

    def test_scan_collect_handles_missing_and_broken_reports(self):
        scans = self.app.scans
        cluster = self.app.store.get_cluster("analytics")
        out = scans.report_dir("manual")
        (out / "an-db-01.json").write_text(json.dumps({
            "schema_version": 1, "os": {"id": "rhel"}, "packages": {"updates_available": 4, "security_updates": 1},
            "pending_updates": [{"name": "openssl", "security": True, "severity": "important"}],
            "compliance": [{"id": "SSH-001", "status": "fail", "severity": "high", "title": "root login"}],
            "reboot_required": True}))
        (out / "an-db-02.json").write_text("{not json")
        outcome = scans.collect(cluster.id, "manual", "full", ["an-db-01", "an-db-02", "an-db-03"], None, False)
        self.assertEqual(outcome["_status"], "partial")
        self.assertEqual(outcome["hosts_scanned"], 1)
        self.assertEqual(outcome["per_host"]["an-db-02"]["status"], "invalid_report")
        self.assertEqual(outcome["per_host"]["an-db-03"]["status"], "no_report")
        self.assertEqual(outcome["hosts_needing_reboot"], ["an-db-01"])
        matrix = scans.compliance("manual")
        self.assertEqual(matrix["checks"][0]["fail"], ["an-db-01"])

    def test_patch_stages_order_primaries_last(self):
        self.app.clusters.set_roles("analytics", {
            "postgresql_primary": ["an-db-01"], "postgresql_replica": ["an-db-02", "an-db-03"]})
        plan = self.app.patches.plan("analytics", {"strategy": "canary", "batch_size": "2"})
        names = [s["name"] for s in plan["stages"]]
        self.assertEqual(names, ["patch canary", "patch standalone hosts", "patch workers and replicas",
                                 "patch primaries"])
        self.assertEqual(plan["stages"][-1], {"name": "patch primaries", "hosts": ["an-db-01"], "serial": 1})
        self.assertEqual(plan["stages"][0]["hosts"], ["an-master-01"])  # least critical, first by name

    def test_all_at_once_with_reboot_blocked_on_clustered_nodes(self):
        self.app.clusters.set_roles("analytics", {"redis_master": ["an-db-01"]})
        with self.assertRaises(ConflictError):
            self.app.patches.apply("analytics", {"strategy": "all_at_once", "reboot": "always"})
        job = self.wait(self.app.patches.apply("analytics", {"strategy": "all_at_once", "reboot": "never"}))
        self.assertEqual(job.status, "success")
        self.assertEqual(job.result["hosts_ok"], 10)
        self.assertIn("post_scan", job.result)

    def test_patch_option_validation(self):
        for body in ({"mode": "packages"}, {"mode": "all", "packages": ["vim"]}, {"reboot": "sometimes"},
                     {"mode": "packages", "packages": ["vim; rm -rf /"]}, {"batch_size": "0"}):
            with self.assertRaises(ValidationError):
                self.app.patches.apply("analytics", body)

    def test_rollback_requires_changed_packages(self):
        job = self.wait(self.app.patches.apply("analytics", {"post_scan": False}))
        with self.assertRaises(ConflictError):
            self.app.patches.rollback(job.id)


class ApiTests(BackendCase):
    def setUp(self):
        super().setUp()
        self.app.settings.api_token = "secret-token"
        self.server = ApiServer(self.app, "127.0.0.1", 0)
        self.auth = {"Authorization": "Bearer secret-token"}

    def tearDown(self):
        self.server.server_close()
        super().tearDown()

    def call(self, method, path, body=None, headers=None):
        raw = json.dumps(body).encode() if body is not None else b""
        return self.server.dispatch(method, path, self.auth if headers is None else headers, raw)

    def test_auth(self):
        self.assertEqual(self.call("GET", "/api/v1/clusters", headers={})[0], 401)
        self.assertEqual(self.call("GET", "/health", headers={})[0], 200)
        self.assertEqual(self.call("GET", "/api/v1/clusters")[0], 200)

    def test_routing_and_errors(self):
        self.assertEqual(self.call("GET", "/api/v1/nope")[0], 404)
        self.assertEqual(self.call("PUT", "/api/v1/clusters")[0], 405)
        self.assertEqual(self.call("GET", "/api/v1/clusters/missing")[0], 404)
        status, _ = self.server.dispatch("POST", "/api/v1/clusters", self.auth, b"{broken")
        self.assertEqual(status, 400)

    def test_job_flow(self):
        status, payload = self.call("POST", "/api/v1/clusters/analytics/versions",
                                    {"technology": "golang", "version": "1.22.5", "nodes": ["an-db-01"]})
        self.assertEqual(status, 202)
        job_id = payload["job"]["id"]
        self.app.jobs.wait(job_id, timeout=30)
        status, job = self.call("GET", "/api/v1/jobs/%s" % job_id)
        self.assertEqual((status, job["status"]), (200, "success"))
        status, log = self.call("GET", "/api/v1/jobs/%s/log?tail=5" % job_id)
        self.assertIn("SIMULATED", log["log"])
        status, plan = self.call("POST", "/api/v1/clusters/analytics/software/hadoop/plan", example("hadoop_ha.json"))
        self.assertEqual((status, plan["mode"]), (200, "ha"))


if __name__ == "__main__":
    unittest.main()
