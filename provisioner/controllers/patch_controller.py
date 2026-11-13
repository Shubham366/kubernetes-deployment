"""Patching of Linux VMs (Ubuntu/Debian, CentOS-like, RHEL).

The hard part of patching a cluster is not running the package manager, it is
not taking the service down while doing so. This controller therefore:

  * orders hosts in tiers - plain nodes first, then workers/replicas, then
    masters/primaries - and only moves to the next tier when the previous one
    succeeded;
  * supports rolling (batch size), canary (a few hosts first) and all-at-once
    strategies, refusing all-at-once with reboots on clusters that run
    clustered software unless forced;
  * collects a per-host report (packages changed, reboot, pre/post checks);
  * can re-scan afterwards and can roll a patch run back.

A patch id is the id of the job that applied it.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..exceptions import ConflictError, NotFoundError, ValidationError
from ..executor import PlaybookResult
from ..jobs import Step
from ..models import Cluster, Job, Node, new_id, now_iso
from .base import BaseController
from .scan_controller import ScanController

PATCH_MODES = ("security", "all", "packages")
REBOOT_POLICIES = ("never", "if_required", "always")
STRATEGIES = ("rolling", "canary", "all_at_once")

# Roles whose loss makes a clustered service unavailable -> patched last.
_PRIMARY_ROLES = {"hadoop_namenode", "hadoop_resourcemanager", "redis_master", "postgresql_primary"}
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:*-]*$")
_OK_STATUSES = ("success", "no_changes", "dry_run", "simulated")


def tier_of(node: Node) -> int:
    """0 = no clustered role, 1 = worker/replica/quorum member, 2 = primary."""
    if not node.roles:
        return 0
    return 2 if _PRIMARY_ROLES & set(node.roles) else 1


def parse_batch_size(value: Any) -> Any:
    """Accept 2, "2" or "25%" - the forms Ansible's ``serial`` accepts."""
    if value is None:
        return 1
    text = str(value).strip()
    if re.match(r"^[1-9][0-9]?%$|^100%$", text):
        return text
    if re.match(r"^[1-9][0-9]*$", text):
        return int(text)
    raise ValidationError("batch_size must be a positive integer or a percentage like '25%%', got %r" % (value,))


class PatchController(BaseController):
    kind = "patch"

    def __init__(self, ctx, scans: ScanController):
        super().__init__(ctx)
        self.scans = scans

    # --------------------------------------------------------------- plan
    def plan(self, ref: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Preview a patch run from the latest (or a given) scan: which hosts
        have pending updates and in which order they would be patched."""
        body = dict(body or {})
        cluster = self.cluster(ref)
        options = self._options(cluster, body)
        scan_id = body.get("scan_id") or self.store.latest_scan_id(cluster.id)
        scan_rows = {r["hostname"]: r for r in self.store.list_scan_results(scan_id)} if scan_id else {}
        warnings = list(options["warnings"])
        if not scan_rows:
            warnings.append("no scan results available: run a scan first to see what would be updated")
        else:
            age_hours = self._age_hours(next(iter(scan_rows.values()))["created_at"])
            if age_hours is not None and age_hours > 24:
                warnings.append("scan %s is %.0f hours old; pending updates may have changed" % (scan_id, age_hours))
            if any(r["status"] == "simulated" for r in scan_rows.values()):
                warnings.append("scan %s was a dry run: its numbers describe no real machine" % scan_id)

        hosts = []
        for node in options["targets"]:
            row = scan_rows.get(node.hostname)
            pending = (row or {}).get("report", {}).get("pending_updates") or []
            if options["mode"] == "security":
                relevant = [p for p in pending if p.get("security")]
            elif options["mode"] == "packages":
                relevant = [p for p in pending if p.get("name") in options["packages"]]
            else:
                relevant = pending
            excluded = set(options["exclude"])
            relevant = [p for p in relevant if p.get("name") not in excluded]
            hosts.append({
                "hostname": node.hostname, "os": "%s %s" % (node.os_type, node.os_version), "tier": tier_of(node),
                "roles": node.roles, "scanned": row is not None and row["status"] == "scanned",
                "packages_to_update": len(relevant),
                "packages": [{"name": p.get("name"), "from": p.get("current_version"),
                              "to": p.get("candidate_version"), "advisory": p.get("advisory", "")}
                             for p in relevant[:50]],
                "reboot_pending": bool(row and row["reboot_required"]),
            })
        return {
            "cluster": cluster.name, "scan_id": scan_id, "mode": options["mode"], "strategy": options["strategy"],
            "batch_size": options["batch_size"], "reboot": options["reboot"],
            "stages": [{"name": s["name"], "hosts": s["hosts"], "serial": s["serial"]}
                       for s in self._stages(options)],
            "hosts": hosts,
            "hosts_with_updates": len([h for h in hosts if h["packages_to_update"]]),
            "warnings": warnings,
        }

    # -------------------------------------------------------------- apply
    def apply(self, ref: str, body: Optional[Dict[str, Any]] = None) -> Job:
        """Patch nodes. ``body`` (all optional)::

            {"mode": "security", "packages": [], "exclude": ["kernel*"],
             "reboot": "if_required", "strategy": "rolling", "batch_size": 1,
             "canary_nodes": ["n5"], "max_fail_percentage": 0, "kernel_update": true,
             "services_to_verify": ["sshd"], "post_scan": true, "nodes": [...],
             "check": false, "force": false}

        ``check`` runs the real scripts on the hosts in their dry-run mode
        (reports what would change); ``dry_run`` does not contact hosts at all.
        """
        body = dict(body or {})
        cluster = self.cluster(ref)
        options = self._options(cluster, body)
        patch_id = new_id()
        out_dir = self.settings.reports_dir / "patches" / patch_id
        out_dir.mkdir(parents=True, exist_ok=True)
        stages = self._stages(options)
        all_hosts = [n.hostname for n in options["targets"]]

        def on_simulate(hosts: List[str], extra: Dict[str, Any]) -> None:
            for hostname in hosts:
                (out_dir / ("%s.json" % hostname)).write_text(json.dumps({
                    "schema_version": 1, "patch_id": patch_id, "hostname": hostname, "simulated": True,
                    "os": {"id": "", "version": ""}, "mode": options["mode"], "dry_run": True,
                    "started_at": now_iso(), "finished_at": now_iso(), "status": "dry_run",
                    "packages_updated": [], "reboot_required": False, "rebooted": False, "transaction_id": "",
                    "pre_check": {"passed": True, "messages": []}, "post_check": {"passed": True, "messages": []},
                    "errors": ["dry run: the host was not contacted"],
                }))

        base_vars = {
            "patch_id": patch_id, "patch_mode": options["mode"], "patch_packages": options["packages"],
            "patch_exclude": options["exclude"], "patch_reboot": options["reboot"],
            "patch_max_fail_percentage": options["max_fail_percentage"], "patch_dry_run": options["check"],
            "patch_kernel_update": options["kernel_update"], "patch_pre_check": options["pre_check"],
            "patch_services_to_verify": options["services_to_verify"], "patch_min_free_mb": options["min_free_mb"],
            "patch_reboot_timeout": options["reboot_timeout"], "patch_output_dir": str(out_dir),
        }
        steps: List[Step] = []
        patch_step_count = len(stages)
        for stage in stages:
            extra = dict(base_vars, patch_serial=stage["serial"])
            # A later stage only runs if every earlier patch stage was clean:
            # never patch the masters after the replicas came back broken.
            steps.append(Step(stage["name"], "patching/patch.yml", extra, limit=stage["hosts"],
                              on_simulate=on_simulate,
                              condition=lambda results: all(r.ok for r in results)))
        post_scan_id = ""
        if options["post_scan"] and not options["check"]:
            post_scan_id = patch_id + "-post"
            steps.append(self.scans.build_step(
                cluster, post_scan_id, "vulnerability", all_hosts, refresh_cache=True, continue_on_failure=True,
                # scan whatever was reached, even if a stage failed
                condition=lambda results: len(results) > 0))

        params = {k: v for k, v in options.items() if k not in ("targets", "warnings")}
        params.update({"nodes": all_hosts, "stages": [dict(s) for s in stages], "warnings": options["warnings"]})

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            patch_results = [r for r in results if r.playbook == "patching/patch.yml"]
            outcome = self._collect(cluster.id, patch_id, all_hosts, out_dir, patch_results, job.dry_run,
                                    stages_run=len(patch_results), stages_total=patch_step_count)
            if post_scan_id:
                scan_results = [r for r in results if r.playbook == "scanning/scan.yml"]
                if scan_results:
                    scan = self.scans.collect(cluster.id, post_scan_id, "vulnerability", all_hosts,
                                              scan_results[-1], job.dry_run)
                    scan.pop("_status", None)
                    scan.pop("per_host", None)
                    outcome["post_scan"] = scan
            outcome["warnings"] = options["warnings"]
            return outcome

        return self.submit(cluster, options["mode"], steps, params=params, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")), job_id=patch_id)

    # ----------------------------------------------------------- rollback
    def rollback(self, patch_id: str, body: Optional[Dict[str, Any]] = None) -> Job:
        """Undo a patch run on the hosts it changed (yum/dnf history undo on
        EL, best-effort package downgrade on Ubuntu/Debian)."""
        body = dict(body or {})
        rows = self.store.list_patch_results(patch_id)
        if not rows:
            raise NotFoundError("no patch results for %s" % patch_id)
        cluster = self.cluster(rows[0]["cluster_id"])
        changed = [r["hostname"] for r in rows if r["packages_updated"] > 0]
        wanted = self.as_list(body.get("nodes"), "nodes") or changed
        not_patched = sorted(set(wanted) - set(changed))
        if not_patched:
            raise ValidationError("patch %s changed no packages on: %s" % (patch_id, ", ".join(not_patched)))
        if not wanted:
            raise ConflictError("patch %s changed no packages; nothing to roll back" % patch_id)
        hosts = [n.hostname for n in cluster.resolve_nodes(wanted)]
        rollback_id = new_id()
        out_dir = self.settings.reports_dir / "rollbacks" / rollback_id
        out_dir.mkdir(parents=True, exist_ok=True)
        extra = {"patch_id": patch_id, "rollback_output_dir": str(out_dir),
                 "patch_serial": parse_batch_size(body.get("batch_size"))}

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            per_host, good = {}, 0
            for hostname in hosts:
                path = out_dir / ("%s.json" % hostname)
                try:
                    report = json.loads(path.read_text())
                except (OSError, ValueError):
                    report = {"status": "simulated" if job.dry_run else "no_report"}
                per_host[hostname] = {"status": report.get("status"),
                                      "packages_reverted": len(report.get("packages_reverted") or []),
                                      "errors": report.get("errors") or []}
                good += report.get("status") == "success"
            outcome: Dict[str, Any] = {"patch_id": patch_id, "rollback_id": rollback_id, "per_host": per_host,
                                       "simulated": job.dry_run,
                                       "note": "kernel downgrades and reboots are not performed automatically"}
            if not job.dry_run and good < len(hosts):
                outcome["_status"] = "partial" if good else "failed"
            return outcome

        return self.submit(cluster, "rollback", [Step("rollback of patch %s" % patch_id, "patching/rollback.yml",
                                                      extra, limit=hosts)],
                           params={"patch_id": patch_id, "nodes": hosts}, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")), job_id=rollback_id)

    # -------------------------------------------------------------- views
    def list(self, ref: str, limit: int = 20) -> List[Dict[str, Any]]:
        cluster = self.cluster(ref)
        out = []
        for job in self.store.list_jobs(cluster_id=cluster.id, kind="patch", limit=limit):
            out.append({"patch_id": job.id, "action": job.action, "status": job.status,
                        "created_at": job.created_at, "finished_at": job.finished_at,
                        "summary": {k: v for k, v in job.result.items() if k not in ("per_host", "post_scan")}})
        return out

    def get(self, patch_id: str, with_reports: bool = False) -> Dict[str, Any]:
        job = self.store.get_job(patch_id)
        if job.kind != "patch":
            raise NotFoundError("job %s is not a patch run" % patch_id)
        return {"patch_id": patch_id, "status": job.status, "params": job.to_dict()["params"],
                "result": job.result, "hosts": self.store.list_patch_results(patch_id, with_report=with_reports)}

    # ------------------------------------------------------------ helpers
    def _options(self, cluster: Cluster, body: Dict[str, Any]) -> Dict[str, Any]:
        mode = str(body.get("mode") or "security").lower()
        if mode not in PATCH_MODES:
            raise ValidationError("mode must be one of: %s" % ", ".join(PATCH_MODES))
        packages = self.as_list(body.get("packages"), "packages")
        exclude = self.as_list(body.get("exclude"), "exclude")
        for pkg in packages + exclude:
            # these end up on a shell command line on the hosts
            if not _PACKAGE_RE.match(pkg):
                raise ValidationError("invalid package name: %r" % pkg)
        if mode == "packages" and not packages:
            raise ValidationError("mode=packages needs a non-empty 'packages' list")
        if mode != "packages" and packages:
            raise ValidationError("'packages' is only valid with mode=packages")
        reboot = str(body.get("reboot") or "if_required").lower()
        if reboot not in REBOOT_POLICIES:
            raise ValidationError("reboot must be one of: %s" % ", ".join(REBOOT_POLICIES))
        strategy = str(body.get("strategy") or "rolling").lower()
        if strategy not in STRATEGIES:
            raise ValidationError("strategy must be one of: %s" % ", ".join(STRATEGIES))
        batch_size = parse_batch_size(body.get("batch_size"))
        targets = cluster.resolve_nodes(body.get("nodes"))
        if not targets:
            raise ValidationError("cluster %s has no active nodes" % cluster.name)
        force = self.as_bool(body.get("force"))
        check = self.as_bool(body.get("check"))
        warnings: List[str] = []

        unreachable = [n.hostname for n in targets if n.state == "unreachable"]
        if unreachable:
            warnings.append("unreachable at last check, will probably fail: %s" % ", ".join(unreachable))

        clustered = [n for n in targets if tier_of(n) > 0]
        if clustered and reboot != "never" and not check:
            if strategy == "all_at_once" and not force:
                raise ConflictError(
                    "strategy=all_at_once with reboot=%s would restart every member of the clustered software "
                    "on %d node(s) at the same time. Use strategy=rolling, set reboot=never, or pass force=true."
                    % (reboot, len(clustered)))
            if strategy != "all_at_once" and batch_size != 1:
                warnings.append("batch_size=%s on nodes running clustered software: make sure the services "
                                "tolerate that many members restarting together" % batch_size)

        canary_nodes: List[str] = []
        if strategy == "canary":
            requested = self.as_list(body.get("canary_nodes"), "canary_nodes")
            if requested:
                canary_nodes = [n.hostname for n in cluster.resolve_nodes(requested)]
                outside = sorted(set(canary_nodes) - {n.hostname for n in targets})
                if outside:
                    raise ValidationError("canary node(s) are not among the targets: %s" % ", ".join(outside))
            else:
                # the least critical host is the cheapest one to break
                canary_nodes = [sorted(targets, key=lambda n: (tier_of(n), n.hostname))[0].hostname]
            if len(canary_nodes) >= len(targets) and len(targets) > 1:
                raise ValidationError("canary_nodes covers every target; that is not a canary")

        return {
            "mode": mode, "packages": packages, "exclude": exclude, "reboot": reboot, "strategy": strategy,
            "batch_size": batch_size, "canary_nodes": canary_nodes, "check": check, "force": force,
            "max_fail_percentage": self.as_int(body.get("max_fail_percentage"), "max_fail_percentage", 0, 0, 100),
            "kernel_update": self.as_bool(body.get("kernel_update"), True),
            "pre_check": self.as_bool(body.get("pre_check"), True),
            "post_scan": self.as_bool(body.get("post_scan"), True),
            "services_to_verify": self.as_list(body.get("services_to_verify"), "services_to_verify"),
            "min_free_mb": self.as_int(body.get("min_free_mb"), "min_free_mb", 1024, 100),
            "reboot_timeout": self.as_int(body.get("reboot_timeout"), "reboot_timeout", 900, 60, 7200),
            "targets": targets, "warnings": warnings,
        }

    @staticmethod
    def _stages(options: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Split the targets into ordered stages; each becomes one playbook run."""
        targets: List[Node] = options["targets"]
        strategy = options["strategy"]
        if strategy == "all_at_once":
            return [{"name": "patch all hosts", "hosts": sorted(n.hostname for n in targets), "serial": "100%"}]
        stages = []
        remaining = list(targets)
        if strategy == "canary":
            canary = options["canary_nodes"]
            stages.append({"name": "patch canary", "hosts": canary, "serial": 1})
            remaining = [n for n in remaining if n.hostname not in canary]
        labels = {0: "patch standalone hosts", 1: "patch workers and replicas", 2: "patch primaries"}
        for tier in (0, 1, 2):
            hosts = sorted(n.hostname for n in remaining if tier_of(n) == tier)
            if hosts:
                # primaries always go one at a time, whatever the batch size
                stages.append({"name": labels[tier], "hosts": hosts,
                               "serial": 1 if tier == 2 else options["batch_size"]})
        return stages

    def _collect(self, cluster_id: str, patch_id: str, hosts: List[str], out_dir, results: List[PlaybookResult],
                 simulated: bool, stages_run: int, stages_total: int) -> Dict[str, Any]:
        unreachable = {h for r in results for h in r.unreachable_hosts}
        attempted = {h for r in results for h in r.recap}
        per_host: Dict[str, Dict[str, Any]] = {}
        for hostname in hosts:
            path = out_dir / ("%s.json" % hostname)
            report: Dict[str, Any]
            try:
                report = json.loads(path.read_text())
                if not isinstance(report, dict):
                    raise ValueError("not an object")
                status = str(report.get("status") or "failed")
                if simulated:
                    status = "simulated"
            except (OSError, ValueError):
                report = {}
                if hostname in unreachable:
                    status = "unreachable"
                elif hostname in attempted:
                    status = "no_report"       # ran, but produced nothing we can trust
                else:
                    status = "not_attempted"   # an earlier stage failed
            self.store.save_patch_result(patch_id, cluster_id, hostname, status, report)
            per_host[hostname] = {
                "status": status,
                "packages_updated": len(report.get("packages_updated") or []),
                "rebooted": bool(report.get("rebooted")),
                "reboot_required": bool(report.get("reboot_required")),
                "errors": report.get("errors") or [],
            }
            for check in ("pre_check", "post_check"):
                if isinstance(report.get(check), dict) and not report[check].get("passed", True):
                    per_host[hostname][check + "_failed"] = report[check].get("messages") or []

        good = [h for h, s in per_host.items() if s["status"] in _OK_STATUSES]
        outcome: Dict[str, Any] = {
            "patch_id": patch_id, "simulated": simulated,
            "hosts_total": len(hosts), "hosts_ok": len(good),
            "hosts_failed": sorted(h for h, s in per_host.items()
                                   if s["status"] in ("failed", "no_report", "unreachable")),
            "hosts_not_attempted": sorted(h for h, s in per_host.items() if s["status"] == "not_attempted"),
            "packages_updated": sum(s["packages_updated"] for s in per_host.values()),
            "hosts_rebooted": sorted(h for h, s in per_host.items() if s["rebooted"]),
            "hosts_still_needing_reboot": sorted(h for h, s in per_host.items()
                                                 if s["reboot_required"] and not s["rebooted"]),
            "stages_run": stages_run, "stages_total": stages_total,
            "per_host": per_host,
        }
        # The reports, not the playbook exit code, decide the outcome.
        if not good:
            outcome["_status"] = "failed"
        elif len(good) < len(hosts):
            outcome["_status"] = "partial"
        return outcome

    @staticmethod
    def _age_hours(timestamp: str) -> Optional[float]:
        try:
            then = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return None
        return (datetime.now(timezone.utc) - then).total_seconds() / 3600.0
