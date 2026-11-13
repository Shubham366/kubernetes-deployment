"""Scanning of Linux VMs: pending (security) updates, compliance checks and
system inventory, on Ubuntu/Debian, CentOS-like and RHEL nodes.

The scan playbook runs a distro-specific script on every node and fetches one
JSON report per host; this controller validates those reports, scores them,
stores them and offers cluster-level views (summary, compliance matrix, diff
between two scans). A scan id is the id of the job that ran it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..exceptions import NotFoundError, ValidationError
from ..executor import PlaybookResult
from ..jobs import Step
from ..models import Cluster, Job, Node, new_id, now_iso
from .base import BaseController

SCAN_TYPES = ("full", "vulnerability", "compliance", "inventory")
_SEVERITY_WEIGHT = {"critical": 10, "high": 6, "important": 6, "medium": 3, "moderate": 3, "low": 1}


def summarize_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Condense one host report into the numbers used for ranking hosts."""
    packages = report.get("packages") or {}
    pending = report.get("pending_updates") or []
    compliance = report.get("compliance") or []
    security = [p for p in pending if p.get("security")]
    failed = [c for c in compliance if c.get("status") == "fail"]

    updates_available = max(int(packages.get("updates_available") or 0), len(pending))
    security_updates = max(int(packages.get("security_updates") or 0), len(security))

    score = 0
    for pkg in security:
        score += _SEVERITY_WEIGHT.get(str(pkg.get("severity", "")).lower(), 4)
    # security updates counted by the script but not itemised
    score += 4 * max(0, security_updates - len(security))
    score += min(10, max(0, updates_available - security_updates))
    for check in failed:
        score += _SEVERITY_WEIGHT.get(str(check.get("severity", "")).lower(), 2)
    if report.get("reboot_required"):
        score += 5
    score = max(0, min(100, score))

    return {
        "updates_available": updates_available,
        "security_updates": security_updates,
        "critical_updates": len([p for p in security if str(p.get("severity", "")).lower() == "critical"]),
        "compliance_total": len(compliance),
        "compliance_failed": len(failed),
        "compliance_warn": len([c for c in compliance if c.get("status") == "warn"]),
        "reboot_required": bool(report.get("reboot_required")),
        "risk_score": score,
        "risk_level": "critical" if score >= 70 else "high" if score >= 40 else "medium" if score >= 15 else "low",
        "errors": len(report.get("errors") or []),
    }


def validate_report(report: Any, hostname: str) -> List[str]:
    """Return problems that make a report unusable (empty list = fine)."""
    if not isinstance(report, dict):
        return ["report is not a JSON object"]
    problems = []
    for key, kind in (("os", dict), ("packages", dict), ("pending_updates", list), ("compliance", list)):
        if key in report and not isinstance(report[key], kind):
            problems.append("field %r has the wrong type" % key)
    if "schema_version" not in report:
        problems.append("missing schema_version")
    return problems


def simulated_report(hostname: str, scan_id: str, scan_type: str, node: Optional[Node]) -> Dict[str, Any]:
    """Placeholder written during dry runs so the rest of the pipeline can be
    exercised. Clearly marked: it describes no real machine."""
    return {
        "schema_version": 1, "scan_id": scan_id, "scan_type": scan_type, "hostname": hostname,
        "timestamp": now_iso(), "simulated": True,
        "os": {"id": node.os_type if node else "unknown", "version": node.os_version if node else "",
               "pretty_name": "simulated", "kernel": "", "arch": ""},
        "packages": {"installed_count": 0, "updates_available": 0, "security_updates": 0},
        "pending_updates": [], "reboot_required": False, "compliance": [],
        "system": {"uptime_seconds": 0, "disk": [], "memory_mb": {"total": 0, "available": 0},
                   "failed_services": [], "listening_ports": []},
        "errors": ["dry run: no data was collected from the host"],
    }


class ScanController(BaseController):
    kind = "scan"

    # ---------------------------------------------------------------- run
    def run(self, ref: str, body: Optional[Dict[str, Any]] = None) -> Job:
        """Start a scan. ``body``: ``{"scan_type": "full", "nodes": [...],
        "refresh_cache": true}``."""
        body = dict(body or {})
        cluster = self.cluster(ref)
        scan_type = str(body.get("scan_type") or "full").lower()
        if scan_type not in SCAN_TYPES:
            raise ValidationError("scan_type must be one of: %s" % ", ".join(SCAN_TYPES))
        targets = cluster.resolve_nodes(body.get("nodes"))
        if not targets:
            raise ValidationError("cluster %s has no active nodes" % cluster.name)
        hosts = [n.hostname for n in targets]
        scan_id = new_id()
        step = self.build_step(cluster, scan_id, scan_type, hosts, self.as_bool(body.get("refresh_cache"), True))

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            return self.collect(cluster.id, scan_id, scan_type, hosts, results[-1] if results else None,
                                job.dry_run)

        return self.submit(cluster, scan_type, [step], params={"scan_type": scan_type, "nodes": hosts},
                           finalize=finalize, dry_run=self.as_bool(body.get("dry_run")), job_id=scan_id)

    def report_dir(self, scan_id: str) -> Path:
        path = self.settings.reports_dir / "scans" / scan_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def build_step(self, cluster: Cluster, scan_id: str, scan_type: str, hosts: List[str],
                   refresh_cache: bool = True, continue_on_failure: bool = False,
                   condition: Optional[Callable[[List[PlaybookResult]], bool]] = None) -> Step:
        """The scan step, reusable by other controllers (post-patch verification)."""
        out_dir = self.report_dir(scan_id)
        by_name = {n.hostname: n for n in cluster.nodes}

        def on_simulate(sim_hosts: List[str], extra: Dict[str, Any]) -> None:
            for hostname in sim_hosts:
                report = simulated_report(hostname, scan_id, scan_type, by_name.get(hostname))
                (out_dir / ("%s.json" % hostname)).write_text(json.dumps(report))

        limit = None if len(hosts) == len(cluster.active_nodes()) else hosts
        return Step(
            "%s scan (%d node(s))" % (scan_type, len(hosts)), "scanning/scan.yml",
            {"scan_id": scan_id, "scan_type": scan_type, "scan_output_dir": str(out_dir),
             "scan_refresh_cache": refresh_cache},
            limit=limit, on_simulate=on_simulate, continue_on_failure=continue_on_failure, condition=condition,
        )

    def collect(self, cluster_id: str, scan_id: str, scan_type: str, hosts: List[str],
                result: Optional[PlaybookResult], simulated: bool) -> Dict[str, Any]:
        """Read the fetched reports, store them and build the cluster summary."""
        out_dir = self.report_dir(scan_id)
        unreachable = set(result.unreachable_hosts) if result else set()
        per_host: Dict[str, Dict[str, Any]] = {}
        scanned = 0
        for hostname in hosts:
            path = out_dir / ("%s.json" % hostname)
            report: Dict[str, Any] = {}
            problems: List[str] = []
            if not path.is_file():
                status = "unreachable" if hostname in unreachable else "no_report"
            else:
                try:
                    report = json.loads(path.read_text())
                    problems = validate_report(report, hostname)
                except ValueError as exc:
                    problems = ["report is not valid JSON: %s" % exc]
                if problems:
                    status, report = "invalid_report", {"errors": problems}
                else:
                    status = "simulated" if (simulated or report.get("simulated")) else "scanned"
            summary = summarize_report(report) if status in ("scanned", "simulated") else {}
            if status in ("scanned", "simulated"):
                scanned += 1
            self.store.save_scan_result(scan_id, cluster_id, hostname, status, summary, report)
            per_host[hostname] = dict(summary, status=status)
            if problems:
                per_host[hostname]["problems"] = problems

        ranked = sorted((h for h, s in per_host.items() if "risk_score" in s),
                        key=lambda h: (-per_host[h]["risk_score"], h))
        outcome: Dict[str, Any] = {
            "scan_id": scan_id, "scan_type": scan_type, "simulated": simulated,
            "hosts_total": len(hosts), "hosts_scanned": scanned,
            "hosts_without_report": sorted(h for h, s in per_host.items()
                                           if s["status"] not in ("scanned", "simulated")),
            "updates_available": sum(s.get("updates_available", 0) for s in per_host.values()),
            "security_updates": sum(s.get("security_updates", 0) for s in per_host.values()),
            "compliance_failed": sum(s.get("compliance_failed", 0) for s in per_host.values()),
            "hosts_needing_reboot": sorted(h for h, s in per_host.items() if s.get("reboot_required")),
            "hosts_by_risk": ranked,
            "per_host": per_host,
        }
        # A scan that produced reports for only some hosts must not look green.
        if scanned == 0:
            outcome["_status"] = "failed"
        elif scanned < len(hosts):
            outcome["_status"] = "partial"
        return outcome

    # -------------------------------------------------------------- views
    def list(self, ref: str, limit: int = 20) -> List[Dict[str, Any]]:
        cluster = self.cluster(ref)
        out = []
        for job in self.store.list_jobs(cluster_id=cluster.id, kind="scan", limit=limit):
            result = {k: v for k, v in job.result.items() if k != "per_host"}
            out.append({"scan_id": job.id, "scan_type": job.action, "status": job.status,
                        "created_at": job.created_at, "finished_at": job.finished_at, "summary": result})
        return out

    def get(self, scan_id: str, with_reports: bool = False, hostname: Optional[str] = None) -> Dict[str, Any]:
        results = self.store.list_scan_results(scan_id, with_report=with_reports or bool(hostname))
        if not results:
            # distinguishes "unknown id" from "scan still running"
            job = self.store.get_job(scan_id)
            return {"scan_id": scan_id, "status": job.status, "hosts": [],
                    "note": "no results stored yet" if not job.finished else job.error}
        if hostname:
            results = [r for r in results if r["hostname"] == hostname]
            if not results:
                raise NotFoundError("no result for host %s in scan %s" % (hostname, scan_id))
        return {"scan_id": scan_id, "cluster_id": results[0]["cluster_id"], "hosts": results}

    def latest(self, ref: str, with_reports: bool = False) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        scan_id = self.store.latest_scan_id(cluster.id)
        if scan_id is None:
            raise NotFoundError("cluster %s has never been scanned" % cluster.name)
        return self.get(scan_id, with_reports)

    def compliance(self, scan_id: str) -> Dict[str, Any]:
        """Check-by-host matrix: which controls fail where."""
        results = self.store.list_scan_results(scan_id, with_report=True)
        if not results:
            raise NotFoundError("no results for scan %s" % scan_id)
        checks: Dict[str, Dict[str, Any]] = {}
        for host in results:
            for check in host["report"].get("compliance") or []:
                entry = checks.setdefault(str(check.get("id")), {
                    "id": check.get("id"), "title": check.get("title", ""), "severity": check.get("severity", ""),
                    "pass": [], "fail": [], "warn": [], "skip": [],
                })
                entry.setdefault(str(check.get("status", "skip")), []).append(host["hostname"])
        ordered = sorted(checks.values(), key=lambda c: (-len(c["fail"]),
                                                         -_SEVERITY_WEIGHT.get(str(c["severity"]).lower(), 0),
                                                         str(c["id"])))
        return {"scan_id": scan_id, "hosts": [h["hostname"] for h in results],
                "checks_total": len(ordered), "checks_failing": len([c for c in ordered if c["fail"]]),
                "checks": ordered}

    def diff(self, old_scan_id: str, new_scan_id: str) -> Dict[str, Any]:
        """What changed between two scans (typically before/after patching)."""
        old = {r["hostname"]: r for r in self.store.list_scan_results(old_scan_id, with_report=True)}
        new = {r["hostname"]: r for r in self.store.list_scan_results(new_scan_id, with_report=True)}
        if not old or not new:
            raise NotFoundError("both scans need stored results to be compared")
        hosts = {}
        for hostname in sorted(set(old) | set(new)):
            a, b = old.get(hostname), new.get(hostname)
            if a is None or b is None:
                hosts[hostname] = {"only_in": "new" if a is None else "old"}
                continue
            before = {p.get("name") for p in a["report"].get("pending_updates") or []}
            after = {p.get("name") for p in b["report"].get("pending_updates") or []}
            failed_before = {c.get("id") for c in a["report"].get("compliance") or [] if c.get("status") == "fail"}
            failed_after = {c.get("id") for c in b["report"].get("compliance") or [] if c.get("status") == "fail"}
            hosts[hostname] = {
                "updates_resolved": sorted(before - after),
                "updates_new": sorted(after - before),
                "updates_remaining": len(after),
                "security_updates": {"before": a["security_updates"], "after": b["security_updates"]},
                "compliance_fixed": sorted(str(c) for c in failed_before - failed_after),
                "compliance_regressed": sorted(str(c) for c in failed_after - failed_before),
                "risk_score": {"before": a["risk_score"], "after": b["risk_score"]},
            }
        return {"old_scan_id": old_scan_id, "new_scan_id": new_scan_id, "hosts": hosts}
