"""Cluster and node lifecycle: registration, connectivity checks, fact
discovery and OS bootstrap for multi-node clusters."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..exceptions import ConflictError, NotFoundError, ValidationError
from ..executor import PlaybookResult
from ..jobs import Step
from ..models import DISTRIBUTION_MAP, Cluster, Job, Node, validate_name, validate_roles
from .base import BaseController

_NODE_DEFAULT_KEYS = ("os_type", "os_version", "ssh_user", "ssh_port", "ssh_key_path", "become")
_BOOTSTRAP_OPTIONS = {
    "bootstrap_timezone": "UTC",
    "bootstrap_packages": [],
    "bootstrap_manage_hosts_file": True,
    "bootstrap_set_hostname": True,
    "bootstrap_ntp_enabled": True,
    "bootstrap_ntp_servers": [],
    "bootstrap_disable_swap": False,
    "bootstrap_upgrade_packages": False,
    "bootstrap_selinux_state": "",          # "", enforcing, permissive, disabled
    "bootstrap_firewall_enabled": None,      # None = leave as is
    "bootstrap_sysctl": {},
    "bootstrap_nofile_limit": 65536,
    "bootstrap_admin_user": "",
    "bootstrap_admin_ssh_public_key": "",
}


class ClusterController(BaseController):
    kind = "cluster"

    # ---------------------------------------------------------------- CRUD
    def create(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cluster. ``spec``::

            {"name": "analytics", "environment": "prod",
             "defaults": {"ssh_user": "ubuntu", "os_type": "ubuntu", "os_version": "22.04"},
             "nodes": [{"hostname": "an-01", "address": "10.0.0.11", "roles": [...]}, ...]}
        """
        if not isinstance(spec, dict):
            raise ValidationError("cluster spec must be an object")
        name = validate_name(spec.get("name"), "cluster name")
        defaults = self._node_defaults(spec.get("defaults"))
        raw_nodes = spec.get("nodes") or []
        if not isinstance(raw_nodes, list):
            raise ValidationError("nodes must be a list")
        nodes = [Node.from_spec(n, defaults) for n in raw_nodes]
        self._check_unique(nodes)
        cluster = Cluster(
            name=name,
            description=str(spec.get("description", "")),
            environment=str(spec.get("environment", "dev")),
            nodes=nodes,
        )
        self.store.create_cluster(cluster)
        return cluster.to_dict()

    def list(self) -> List[Dict[str, Any]]:
        return [c.to_dict(with_nodes=False) for c in self.store.list_clusters()]

    def get(self, ref: str) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        data = cluster.to_dict()
        data["installations"] = self.store.list_installations(cluster.id)
        for item in data["installations"]:
            item.pop("params", None)
        data["active_jobs"] = [j.id for j in self.jobs.active_jobs(cluster.id)]
        return data

    def delete(self, ref: str, force: bool = False) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        if self.jobs.active_jobs(cluster.id):
            raise ConflictError("cluster %s has jobs in progress; cancel them first" % cluster.name)
        installed = [i for i in self.store.list_installations(cluster.id, "software")
                     if i["state"] in ("installed", "installing")]
        if installed and not force:
            raise ConflictError(
                "cluster %s still has software deployed (%s). Uninstall it first or pass force=true. "
                "Deleting only removes the record; nothing is removed from the machines."
                % (cluster.name, ", ".join(sorted({i["name"] for i in installed})))
            )
        self.store.delete_cluster(cluster.id)
        return {"deleted": cluster.name, "nodes_removed_from_inventory": len(cluster.nodes)}

    # --------------------------------------------------------------- nodes
    def add_nodes(self, ref: str, body: Dict[str, Any]) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        raw_nodes = self.require(body, "nodes")
        if not isinstance(raw_nodes, list):
            raise ValidationError("nodes must be a list")
        defaults = self._node_defaults(body.get("defaults"))
        nodes = [Node.from_spec(n, defaults) for n in raw_nodes]
        self._check_unique(cluster.nodes + nodes)
        self.store.add_nodes(cluster.id, nodes)
        return self.cluster(cluster.id).to_dict()

    def update_node(self, ref: str, node_ref: str, body: Dict[str, Any]) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        node = cluster.find_node(node_ref)
        if node is None:
            raise NotFoundError("node %s not found in cluster %s" % (node_ref, cluster.name))
        allowed = {"address", "os_type", "os_version", "ssh_user", "ssh_port", "ssh_key_path", "become",
                   "roles", "labels"}
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise ValidationError("fields cannot be updated: %s" % ", ".join(unknown))
        merged = node.to_dict()
        merged.update(body)
        updated = Node.from_spec(merged)
        for key in allowed:
            setattr(node, key, getattr(updated, key))
        self._check_unique(cluster.nodes)
        self.store.save_node(node)
        return node.to_dict()

    def remove_node(self, ref: str, node_ref: str, force: bool = False) -> Dict[str, Any]:
        cluster = self.cluster(ref)
        node = cluster.find_node(node_ref)
        if node is None:
            raise NotFoundError("node %s not found in cluster %s" % (node_ref, cluster.name))
        if node.roles and not force:
            raise ConflictError(
                "node %s still carries roles (%s). Decommission it from the software first, or pass "
                "force=true to drop it from the inventory anyway." % (node.hostname, ", ".join(node.roles))
            )
        self.store.delete_node(node.id)
        return {"removed": node.hostname, "had_roles": node.roles}

    def set_roles(self, ref: str, assignment: Dict[str, List[str]], replace_prefix: Optional[str] = None) -> None:
        """Apply ``{role: [hostnames]}``. With ``replace_prefix`` every existing
        role starting with that prefix is dropped first, so the assignment
        becomes the complete layout for that software."""
        cluster = self.cluster(ref)
        wanted: Dict[str, set] = {}
        for role, hostnames in assignment.items():
            validate_roles([role])
            for node in cluster.resolve_nodes(list(hostnames)):
                wanted.setdefault(node.id, set()).add(role)
        for node in cluster.nodes:
            roles = set(node.roles)
            if replace_prefix:
                roles = {r for r in roles if not r.startswith(replace_prefix)}
            roles |= wanted.get(node.id, set())
            if sorted(roles) != node.roles:
                node.roles = sorted(roles)
                self.store.save_node(node)

    # ---------------------------------------------------------- operations
    def ping(self, ref: str, nodes: Optional[List[str]] = None, dry_run: bool = False) -> Job:
        cluster = self.cluster(ref)
        targets = cluster.resolve_nodes(nodes)
        self._require_nodes(cluster, targets)

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            if job.dry_run or not results:
                return {"simulated": job.dry_run}
            result = results[0]
            reachable, unreachable = result.ok_hosts, sorted(set(result.failed_hosts + result.unreachable_hosts))
            fresh = self.cluster(cluster.id)
            for node in fresh.nodes:
                if node.hostname in unreachable:
                    node.state = "unreachable"
                elif node.hostname in reachable and node.state in ("registered", "unreachable"):
                    node.state = "reachable"
                else:
                    continue
                self.store.save_node(node)
            self._refresh_cluster_state(cluster.id)
            return {"reachable": reachable, "unreachable": unreachable}

        return self.submit(cluster, "ping", [Step("ping", "cluster/ping.yml", limit=self._limit(cluster, targets))],
                           params={"nodes": [n.hostname for n in targets]}, finalize=finalize, dry_run=dry_run)

    def gather_facts(self, ref: str, nodes: Optional[List[str]] = None, dry_run: bool = False) -> Job:
        """Discover the real OS, kernel, CPU, memory and disks of every node and
        correct the declared ``os_type``/``os_version`` where they differ."""
        cluster = self.cluster(ref)
        targets = cluster.resolve_nodes(nodes)
        self._require_nodes(cluster, targets)
        holder: Dict[str, Path] = {}

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            if job.dry_run:
                return {"simulated": True}
            out_dir = holder["dir"]
            fresh = self.cluster(cluster.id)
            collected, corrected, missing = [], [], []
            for node in fresh.nodes:
                if node.hostname not in [t.hostname for t in targets]:
                    continue
                path = out_dir / ("%s.json" % node.hostname)
                try:
                    facts = json.loads(path.read_text())
                except (OSError, ValueError):
                    missing.append(node.hostname)
                    continue
                node.facts = facts
                detected = DISTRIBUTION_MAP.get(str(facts.get("distribution", "")).lower().replace(" ", ""))
                version = str(facts.get("distribution_version", "") or "")
                if detected and (detected != node.os_type or (version and version != node.os_version)):
                    corrected.append({"hostname": node.hostname, "declared": "%s %s" % (node.os_type, node.os_version),
                                      "detected": "%s %s" % (detected, version)})
                    node.os_type, node.os_version = detected, version or node.os_version
                if node.state in ("registered", "unreachable"):
                    node.state = "reachable"
                self.store.save_node(node)
                collected.append(node.hostname)
            self._refresh_cluster_state(cluster.id)
            outcome: Dict[str, Any] = {"collected": collected, "corrected": corrected, "missing": missing}
            if missing and collected:
                outcome["_status"] = "partial"
            return outcome

        # The output dir depends on the job id, which only exists after submit;
        # use a per-cluster directory that is unique enough and record it.
        out_dir = self.settings.reports_dir / "facts" / cluster.name
        out_dir.mkdir(parents=True, exist_ok=True)
        for stale in out_dir.glob("*.json"):
            stale.unlink()
        holder["dir"] = out_dir
        step = Step("gather facts", "cluster/gather_facts.yml", {"facts_output_dir": str(out_dir)},
                    limit=self._limit(cluster, targets))
        return self.submit(cluster, "gather_facts", [step], params={"nodes": [n.hostname for n in targets]},
                           finalize=finalize, dry_run=dry_run)

    def bootstrap(self, ref: str, body: Optional[Dict[str, Any]] = None, dry_run: bool = False) -> Job:
        """Baseline OS configuration shared by all software: hostnames,
        /etc/hosts for every cluster member, time sync, base packages, limits."""
        body = dict(body or {})
        cluster = self.cluster(ref)
        targets = cluster.resolve_nodes(body.pop("nodes", None))
        self._require_nodes(cluster, targets)
        body.pop("dry_run", None)
        unknown = sorted(set(body) - set(_BOOTSTRAP_OPTIONS))
        if unknown:
            raise ValidationError("unknown bootstrap option(s): %s" % ", ".join(unknown))
        extra = {k: body.get(k, default) for k, default in _BOOTSTRAP_OPTIONS.items()
                 if body.get(k, default) is not None}
        if extra.get("bootstrap_selinux_state") not in ("", "enforcing", "permissive", "disabled"):
            raise ValidationError("bootstrap_selinux_state must be enforcing, permissive or disabled")
        if not isinstance(extra["bootstrap_packages"], list) or not isinstance(extra["bootstrap_sysctl"], dict):
            raise ValidationError("bootstrap_packages must be a list and bootstrap_sysctl an object")
        # /etc/hosts must list every member, including nodes outside this run.
        extra["bootstrap_cluster_hosts"] = [
            {"hostname": n.hostname, "address": n.address} for n in cluster.active_nodes()
        ]

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            if job.dry_run or not results:
                return {"simulated": job.dry_run}
            done = results[-1].ok_hosts
            fresh = self.cluster(cluster.id)
            for node in fresh.nodes:
                if node.hostname in done:
                    node.state = "bootstrapped"
                    self.store.save_node(node)
            self._refresh_cluster_state(cluster.id)
            return {"bootstrapped": done, "failed": results[-1].failed_hosts,
                    "unreachable": results[-1].unreachable_hosts}

        steps = [
            Step("connectivity check", "cluster/ping.yml", limit=self._limit(cluster, targets)),
            Step("bootstrap", "cluster/bootstrap.yml", extra, limit=self._limit(cluster, targets)),
        ]
        return self.submit(cluster, "bootstrap", steps, params=extra, finalize=finalize, dry_run=dry_run)

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _node_defaults(raw: Any) -> Dict[str, Any]:
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise ValidationError("defaults must be an object")
        unknown = sorted(set(raw) - set(_NODE_DEFAULT_KEYS))
        if unknown:
            raise ValidationError("unsupported node default(s): %s" % ", ".join(unknown))
        return dict(raw)

    @staticmethod
    def _check_unique(nodes: List[Node]) -> None:
        seen_hosts, seen_addr = set(), set()
        for node in nodes:
            if node.hostname in seen_hosts:
                raise ValidationError("duplicate node hostname: %s" % node.hostname)
            if (node.address, node.ssh_port) in seen_addr:
                raise ValidationError("duplicate node address: %s:%s" % (node.address, node.ssh_port))
            seen_hosts.add(node.hostname)
            seen_addr.add((node.address, node.ssh_port))

    @staticmethod
    def _require_nodes(cluster: Cluster, targets: List[Node]) -> None:
        if not targets:
            raise ValidationError("cluster %s has no active nodes" % cluster.name)

    @staticmethod
    def _limit(cluster: Cluster, targets: List[Node]) -> Optional[List[str]]:
        """No --limit when everything is targeted (keeps the command short)."""
        if len(targets) == len(cluster.active_nodes()):
            return None
        return [n.hostname for n in targets]

    def _refresh_cluster_state(self, cluster_id: str) -> None:
        cluster = self.cluster(cluster_id)
        active = cluster.active_nodes()
        if not active:
            state = "new"
        elif any(n.state == "unreachable" for n in active):
            state = "degraded"
        elif all(n.state in ("reachable", "bootstrapped") for n in active):
            state = "ready"
        else:
            state = "new"
        if state != cluster.state:
            self.store.update_cluster(cluster.id, state=state)
