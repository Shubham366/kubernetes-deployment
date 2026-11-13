"""Clustered software lifecycle: multi-node Hadoop, Redis and PostgreSQL.

Responsibilities:
  * turn a deployment request into a validated role layout (who is NameNode,
    who is a replica ...), proposing one when the caller gives none;
  * reject topologies that cannot work before any machine is touched;
  * run prerequisites (the JDK for Hadoop) and then the software playbook;
  * day-2 operations: start/stop/restart/status, scale-out, decommission,
    PostgreSQL promote, uninstall;
  * remember what was deployed with which variables so later operations use
    the same configuration (and the same generated passwords).
"""
from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from ..catalog import (SOFTWARE, auto_assign_roles, get_software, hadoop_java_version, resolve_install_method,
                       validate_topology)
from ..exceptions import ConflictError, NotFoundError, ValidationError
from ..executor import PlaybookResult
from ..jobs import Step
from ..models import Cluster, Job, Node, mask_secrets
from .base import BaseController
from .cluster_controller import ClusterController

_SIMPLE_ACTIONS = ("start", "stop", "restart", "status")


class SoftwareController(BaseController):
    kind = "software"

    def __init__(self, ctx, clusters: ClusterController):
        super().__init__(ctx)
        self.clusters = clusters

    # ------------------------------------------------------------ queries
    def catalog(self) -> Dict[str, Any]:
        return {name: {k: v for k, v in spec.items() if k not in ("playbook", "var_prefix")}
                for name, spec in sorted(SOFTWARE.items())}

    def list_deployed(self, ref: str) -> List[Dict[str, Any]]:
        cluster = self.cluster(ref)
        out = []
        for item in self.store.list_installations(cluster.id, "software"):
            item["params"] = mask_secrets(item["params"])
            out.append(item)
        return out

    def plan(self, ref: str, name: str, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a deployment request and show the layout that would be
        used, without submitting anything."""
        cluster = self.cluster(ref)
        resolved = self._resolve(cluster, name, body)
        return {
            "software": name, "version": resolved["version"], "mode": resolved["mode"],
            "roles": resolved["roles"], "warnings": resolved["warnings"],
            "vars": mask_secrets(resolved["vars"]),
            "prerequisites": resolved["prerequisites"],
        }

    # ------------------------------------------------------------- deploy
    def deploy(self, ref: str, name: str, body: Optional[Dict[str, Any]] = None) -> Job:
        """Install (or re-apply the configuration of) a software cluster.

        ``body``::

            {"version": "3.3.6", "mode": "ha",
             "roles": {"hadoop_namenode": ["n1"], "hadoop_datanode": ["n3", "n4"], ...},
             "nodes": ["n1", ...],        # pool for automatic layout when roles is omitted
             "vars": {"hadoop_replication_factor": 3},
             "install_java": true}
        """
        body = dict(body or {})
        cluster = self.cluster(ref)
        spec = get_software(name)
        resolved = self._resolve(cluster, name, body)
        dry_run = self.as_bool(body.get("dry_run"))
        simulated = self.is_simulated(dry_run)

        previous = self.store.get_installation(cluster.id, "software", name)
        if previous and previous["state"] == "installed":
            old_mode = previous["params"].get("mode")
            if old_mode and old_mode != resolved["mode"]:
                raise ConflictError(
                    "%s is already deployed in mode %r; converting to %r in place is not supported. "
                    "Uninstall first (data is kept unless purge_data is set)." % (name, old_mode, resolved["mode"]))

        steps = self._prerequisite_steps(cluster, name, resolved)
        extra = dict(resolved["vars"])
        extra["%s_action" % spec["var_prefix"]] = "install"
        steps.append(Step("%s install" % name, spec["playbook"], extra))

        record = {"mode": resolved["mode"], "roles": resolved["roles"], "vars": resolved["vars"]}
        if not simulated:
            # Roles drive the inventory groups the playbook targets.
            self.clusters.set_roles(cluster.id, resolved["roles"], replace_prefix=spec["var_prefix"] + "_")
            self.store.upsert_installation(cluster.id, "", "software", name, resolved["version"],
                                           "installing", record)

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            ok = bool(results) and all(r.ok for r in results) and len(results) == len(steps)
            outcome = {"software": name, "version": resolved["version"], "mode": resolved["mode"],
                       "roles": resolved["roles"], "warnings": resolved["warnings"], "simulated": job.dry_run,
                       "deployed": ok and not job.dry_run}
            if not job.dry_run:
                self.store.upsert_installation(cluster.id, "", "software", name, resolved["version"],
                                               "installed" if ok else "failed", record, job.id)
            return outcome

        params = {"software": name, "version": resolved["version"], "mode": resolved["mode"],
                  "roles": resolved["roles"], "vars": resolved["vars"], "warnings": resolved["warnings"]}
        return self.submit(cluster, "install", steps, params=params, finalize=finalize, dry_run=dry_run,
                           extra_groups=resolved["roles"])

    # ------------------------------------------------------- day-2 actions
    def action(self, ref: str, name: str, action: str, body: Optional[Dict[str, Any]] = None) -> Job:
        """Dispatch any catalog action for a deployed software."""
        body = dict(body or {})
        spec = get_software(name)
        if action not in spec["actions"]:
            raise ValidationError("%s does not support action %r (valid: %s)"
                                  % (name, action, ", ".join(spec["actions"])))
        if action == "install":
            return self.deploy(ref, name, body)
        if action in ("scale_out", "add_replica"):
            return self.scale_out(ref, name, body)
        if action == "decommission":
            return self.decommission(ref, name, body)
        if action == "promote":
            return self.promote(ref, name, body)
        if action == "uninstall":
            return self.uninstall(ref, name, body)

        cluster = self.cluster(ref)
        installation = self._installation(cluster, name)
        extra = self._base_vars(name, installation)
        extra["%s_action" % spec["var_prefix"]] = action
        limit = None
        if body.get("nodes"):
            members = self._member_hostnames(cluster, spec)
            limit = [n.hostname for n in cluster.resolve_nodes(body["nodes"])]
            outsiders = sorted(set(limit) - members)
            if outsiders:
                raise ValidationError("node(s) are not part of the %s deployment: %s" % (name, ", ".join(outsiders)))

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            result = results[0] if results else None
            return {"software": name, "action": action, "simulated": job.dry_run,
                    "ok_hosts": result.ok_hosts if result else [],
                    "failed_hosts": result.failed_hosts if result else [],
                    "unreachable_hosts": result.unreachable_hosts if result else [],
                    "note": "status output is in the job log" if action == "status" else ""}

        return self.submit(cluster, action, [Step("%s %s" % (name, action), spec["playbook"], extra, limit=limit)],
                           params={"software": name, "nodes": limit or "all"}, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")))

    def scale_out(self, ref: str, name: str, body: Dict[str, Any]) -> Job:
        """Add nodes to a running deployment. ``body``: ``{"roles": {role: [hostnames]}}``
        where the roles are the software's scalable ones (DataNodes, replicas,
        Redis Cluster members)."""
        cluster = self.cluster(ref)
        spec = get_software(name)
        installation = self._installation(cluster, name, must_be_installed=True)
        mode = installation["params"].get("mode", spec["default_mode"])
        additions = self.require(body, "roles")
        if not isinstance(additions, dict):
            raise ValidationError("roles must be an object of {role: [hostnames]}")

        current = self._current_assignment(cluster, spec)
        merged = {role: list(nodes) for role, nodes in current.items()}
        new_hosts: List[str] = []
        new_roles: Dict[str, List[str]] = {}
        for role, refs in additions.items():
            if role not in spec["scale_roles"]:
                raise ValidationError("%s can only be scaled by adding: %s" % (name, ", ".join(spec["scale_roles"])))
            for node in cluster.resolve_nodes(self.as_list(refs, role)):
                if role in node.roles:
                    raise ConflictError("node %s already has role %s" % (node.hostname, role))
                if name != "hadoop" and any(r.startswith(spec["var_prefix"] + "_") for r in node.roles):
                    raise ConflictError("node %s already takes part in the %s deployment as %s"
                                        % (node.hostname, name, ", ".join(node.roles)))
                merged.setdefault(role, []).append(node)
                new_roles.setdefault(role, []).append(node.hostname)
                if node.hostname not in new_hosts:
                    new_hosts.append(node.hostname)
        if not new_hosts:
            raise ValidationError("no nodes to add")
        if name == "redis" and mode == "standalone":
            raise ValidationError("a standalone Redis cannot be scaled; redeploy with mode=replication")
        if name == "postgresql" and mode == "standalone":
            mode = "replication"  # first replica turns it into a replicated setup

        vars_ = dict(installation["params"].get("vars", {}))
        if name == "postgresql":
            vars_["postgresql_mode"] = mode
            vars_.setdefault("postgresql_replication_password", secrets.token_urlsafe(24))
        warnings = validate_topology(name, mode, installation["version"], merged, vars_)

        action = "add_replica" if name == "postgresql" else "scale_out"
        extra = dict(vars_)
        extra["%s_action" % spec["var_prefix"]] = action
        extra["postgresql_new_replicas" if name == "postgresql" else "%s_new_nodes" % spec["var_prefix"]] = new_hosts

        resolved = {"vars": vars_, "version": installation["version"],
                    "roles": {r: [n.hostname for n in ns] for r, ns in merged.items()}}
        steps = self._prerequisite_steps(cluster, name, resolved, only_hosts=new_hosts)
        steps.append(Step("%s %s" % (name, action), spec["playbook"], extra))

        dry_run = self.as_bool(body.get("dry_run"))
        if not self.is_simulated(dry_run):
            self.clusters.set_roles(cluster.id, new_roles)
        record = {"mode": mode, "roles": resolved["roles"], "vars": vars_}

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            ok = bool(results) and all(r.ok for r in results) and len(results) == len(steps)
            if not job.dry_run and ok:
                self.store.upsert_installation(cluster.id, "", "software", name, installation["version"],
                                               "installed", record, job.id)
            return {"software": name, "added": new_roles, "succeeded": ok, "warnings": warnings,
                    "simulated": job.dry_run,
                    "note": "" if ok or job.dry_run else
                    "new nodes keep their roles so the operation can be retried; remove the roles to abandon it"}

        return self.submit(cluster, action, steps, params={"software": name, "added": new_roles},
                           finalize=finalize, dry_run=dry_run, extra_groups=resolved["roles"])

    def decommission(self, ref: str, name: str, body: Dict[str, Any]) -> Job:
        """Gracefully drain and remove Hadoop DataNodes."""
        if name != "hadoop":
            raise ValidationError("decommission is only implemented for hadoop")
        cluster = self.cluster(ref)
        spec = get_software(name)
        installation = self._installation(cluster, name, must_be_installed=True)
        targets = cluster.resolve_nodes(self.as_list(self.require(body, "nodes"), "nodes"))
        not_datanodes = [n.hostname for n in targets if "hadoop_datanode" not in n.roles]
        if not_datanodes:
            raise ValidationError("not DataNodes: %s" % ", ".join(not_datanodes))
        vars_ = dict(installation["params"].get("vars", {}))
        remaining = len(cluster.nodes_with_role("hadoop_datanode")) - len(targets)
        replication = int(vars_.get("hadoop_replication_factor", 3))
        if remaining < replication:
            raise ValidationError(
                "decommissioning would leave %d DataNode(s) but hadoop_replication_factor is %d; "
                "blocks could not be re-replicated and the decommission would never finish"
                % (remaining, replication))
        hosts = [n.hostname for n in targets]
        extra = dict(vars_)
        extra.update({"hadoop_action": "decommission", "hadoop_decommission_nodes": hosts})

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            ok = bool(results) and results[0].ok
            if ok and not job.dry_run:
                fresh = self.cluster(cluster.id)
                for node in fresh.nodes:
                    if node.hostname in hosts and "hadoop_datanode" in node.roles:
                        node.roles = [r for r in node.roles if r != "hadoop_datanode"]
                        self.store.save_node(node)
                record = dict(installation["params"])
                record["roles"] = {r: [n.hostname for n in ns]
                                   for r, ns in self._current_assignment(self.cluster(cluster.id), spec).items()}
                self.store.upsert_installation(cluster.id, "", "software", name, installation["version"],
                                               "installed", record, job.id)
            return {"software": name, "decommissioned": hosts if ok else [], "simulated": job.dry_run,
                    "remaining_datanodes": remaining}

        return self.submit(cluster, "decommission", [Step("hadoop decommission", spec["playbook"], extra)],
                           params={"software": name, "nodes": hosts}, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")))

    def promote(self, ref: str, name: str, body: Dict[str, Any]) -> Job:
        """Promote a PostgreSQL replica to primary (planned switchover or
        failover after the primary died)."""
        if name != "postgresql":
            raise ValidationError("promote is only implemented for postgresql")
        cluster = self.cluster(ref)
        spec = get_software(name)
        installation = self._installation(cluster, name, must_be_installed=True)
        node = cluster.resolve_nodes([str(self.require(body, "node"))])[0]
        if "postgresql_replica" not in node.roles:
            raise ValidationError("node %s is not a PostgreSQL replica" % node.hostname)
        old_primaries = [n.hostname for n in cluster.nodes_with_role("postgresql_primary")]
        extra = dict(installation["params"].get("vars", {}))
        extra.update({"postgresql_action": "promote", "postgresql_promote_host": node.hostname})

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            ok = bool(results) and results[0].ok
            if ok and not job.dry_run:
                fresh = self.cluster(cluster.id)
                for member in fresh.nodes:
                    roles = set(member.roles)
                    if member.hostname == node.hostname:
                        roles.discard("postgresql_replica")
                        roles.add("postgresql_primary")
                    elif member.hostname in old_primaries:
                        # The old primary must be rebuilt as a replica before it
                        # may rejoin; until then it has no role.
                        roles.discard("postgresql_primary")
                    if sorted(roles) != member.roles:
                        member.roles = sorted(roles)
                        self.store.save_node(member)
                record = dict(installation["params"])
                record["roles"] = {r: [n.hostname for n in ns]
                                   for r, ns in self._current_assignment(self.cluster(cluster.id), spec).items()}
                self.store.upsert_installation(cluster.id, "", "software", name, installation["version"],
                                               "installed", record, job.id)
            return {"software": name, "promoted": node.hostname if ok else None, "simulated": job.dry_run,
                    "old_primary": old_primaries,
                    "note": "the old primary was removed from the layout; re-add it with add_replica "
                            "(its data directory will be re-synchronised)" if ok else ""}

        return self.submit(cluster, "promote", [Step("postgresql promote", spec["playbook"], extra)],
                           params={"software": name, "node": node.hostname}, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")))

    def uninstall(self, ref: str, name: str, body: Optional[Dict[str, Any]] = None) -> Job:
        body = dict(body or {})
        cluster = self.cluster(ref)
        spec = get_software(name)
        installation = self._installation(cluster, name)
        purge = self.as_bool(body.get("purge_data"))
        if purge and not self.as_bool(body.get("confirm_purge")):
            raise ValidationError(
                "purge_data deletes the %s data directories on every node and cannot be undone; "
                "repeat the request with confirm_purge=true" % name)
        prefix = spec["var_prefix"]
        extra = self._base_vars(name, installation)
        extra.update({"%s_action" % prefix: "uninstall", "%s_purge_data" % prefix: purge})

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            result = results[0] if results else None
            ok = bool(result and result.ok)
            if ok and not job.dry_run:
                fresh = self.cluster(cluster.id)
                for node in fresh.nodes:
                    kept = [r for r in node.roles if not r.startswith(prefix + "_")]
                    if kept != node.roles:
                        node.roles = kept
                        self.store.save_node(node)
                self.store.set_installation_state(cluster.id, "", "software", name, "removed")
            return {"software": name, "removed": ok, "data_purged": bool(ok and purge), "simulated": job.dry_run,
                    "failed_hosts": result.failed_hosts if result else [],
                    "unreachable_hosts": result.unreachable_hosts if result else []}

        return self.submit(cluster, "uninstall", [Step("%s uninstall" % name, spec["playbook"], extra)],
                           params={"software": name, "purge_data": purge}, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")))

    # ------------------------------------------------------------- helpers
    def _resolve(self, cluster: Cluster, name: str, body: Dict[str, Any]) -> Dict[str, Any]:
        spec = get_software(name)
        prefix = spec["var_prefix"]
        version = str(body.get("version") or spec["default_version"])
        if version not in spec["versions"] and not self.as_bool(body.get("allow_unlisted")):
            raise ValidationError("%s version %r is not in the catalog (%s); pass allow_unlisted=true to try it"
                                  % (name, version, ", ".join(spec["versions"])))
        mode = str(body.get("mode") or spec["default_mode"]).lower()
        if mode not in spec["modes"]:
            raise ValidationError("%s mode must be one of: %s" % (name, ", ".join(spec["modes"])))

        user_vars = body.get("vars") or {}
        if not isinstance(user_vars, dict):
            raise ValidationError("vars must be an object")
        reserved = {prefix + "_action", prefix + "_version", prefix + "_mode", "hadoop_ha_enabled",
                    prefix + "_new_nodes", "postgresql_new_replicas", "hadoop_decommission_nodes",
                    "postgresql_promote_host", prefix + "_purge_data"}
        for key in user_vars:
            if not str(key).startswith(prefix + "_"):
                raise ValidationError("variable %r must start with %r" % (key, prefix + "_"))
            if key in reserved:
                raise ValidationError("variable %r is controlled by the backend" % key)

        # Layout: explicit, or proposed from the node pool.
        raw_roles = body.get("roles")
        if raw_roles:
            if not isinstance(raw_roles, dict):
                raise ValidationError("roles must be an object of {role: [hostnames]}")
            layout = {str(r): self.as_list(h, str(r)) for r, h in raw_roles.items() if h}
        else:
            pool = cluster.resolve_nodes(body.get("nodes"))
            layout = auto_assign_roles(name, mode, pool, user_vars)
        assignment: Dict[str, List[Node]] = {r: cluster.resolve_nodes(h) for r, h in layout.items()}

        # Variables: stored ones (so passwords survive re-runs) < request.
        previous = self.store.get_installation(cluster.id, "software", name)
        stored = previous["params"].get("vars", {}) if previous and previous["state"] != "removed" else {}
        vars_: Dict[str, Any] = {k: v for k, v in stored.items() if "password" in k}
        vars_.update(user_vars)
        vars_["%s_version" % prefix] = version

        prerequisites: List[str] = []
        if name == "hadoop":
            vars_["hadoop_ha_enabled"] = mode == "ha"
            vars_.setdefault("hadoop_cluster_name", cluster.name.replace("_", "-"))
            datanodes = len(assignment.get("hadoop_datanode", []))
            vars_.setdefault("hadoop_replication_factor", min(3, max(1, datanodes)))
            java = hadoop_java_version(version, vars_.get("hadoop_java_version"))
            vars_["hadoop_java_version"] = int(java)
            if self.as_bool(body.get("install_java"), True):
                prerequisites.append("java %s" % java)
        elif name == "redis":
            vars_["redis_mode"] = mode
            if mode != "standalone":
                # replicas authenticate to the master, so a shared password is needed
                vars_.setdefault("redis_password", secrets.token_urlsafe(24))
        elif name == "postgresql":
            vars_["postgresql_mode"] = mode
            vars_.setdefault("postgresql_superuser_password", secrets.token_urlsafe(24))
            if mode == "replication":
                vars_.setdefault("postgresql_replication_password", secrets.token_urlsafe(24))

        warnings = validate_topology(name, mode, version, assignment, vars_)
        unreachable = sorted({n.hostname for ns in assignment.values() for n in ns if n.state == "unreachable"})
        if unreachable:
            raise ConflictError("node(s) were unreachable at the last check: %s. Fix connectivity and run "
                                "'cluster ping' again before deploying." % ", ".join(unreachable))
        return {
            "version": version, "mode": mode, "vars": vars_, "warnings": warnings,
            "roles": {r: [n.hostname for n in ns] for r, ns in sorted(assignment.items())},
            "prerequisites": prerequisites,
            "install_java": self.as_bool(body.get("install_java"), True),
        }

    def _prerequisite_steps(self, cluster: Cluster, name: str, resolved: Dict[str, Any],
                            only_hosts: Optional[List[str]] = None) -> List[Step]:
        """Hadoop needs a JDK on every member; install it with the method that
        fits each node's OS."""
        if name != "hadoop" or not resolved.get("install_java", True):
            return []
        version = str(resolved["vars"].get("hadoop_java_version", 11))
        members = sorted({h for hosts in resolved["roles"].values() for h in hosts})
        if only_hosts is not None:
            members = [h for h in members if h in only_hosts]
        by_method: Dict[str, List[str]] = {}
        for node in cluster.resolve_nodes(members) if members else []:
            method, _ = resolve_install_method("java", version, node)
            by_method.setdefault(method, []).append(node.hostname)
        return [
            Step("java %s via %s (%d node(s))" % (version, method, len(hosts)), "versions/java.yml",
                 {"java_version": version, "java_state": "present", "java_install_method": method,
                  "java_set_default": True}, limit=hosts)
            for method, hosts in sorted(by_method.items())
        ]

    def _installation(self, cluster: Cluster, name: str, must_be_installed: bool = False) -> Dict[str, Any]:
        installation = self.store.get_installation(cluster.id, "software", name)
        if installation is None or installation["state"] == "removed":
            raise NotFoundError("%s is not deployed on cluster %s" % (name, cluster.name))
        if must_be_installed and installation["state"] != "installed":
            raise ConflictError("%s on cluster %s is in state %r; finish or repair the installation first"
                                % (name, cluster.name, installation["state"]))
        return installation

    @staticmethod
    def _base_vars(name: str, installation: Dict[str, Any]) -> Dict[str, Any]:
        vars_ = dict(installation["params"].get("vars", {}))
        vars_.setdefault("%s_version" % SOFTWARE[name]["var_prefix"], installation["version"])
        return vars_

    @staticmethod
    def _current_assignment(cluster: Cluster, spec: Dict[str, Any]) -> Dict[str, List[Node]]:
        return {role: nodes for role in spec["roles"] for nodes in [cluster.nodes_with_role(role)] if nodes}

    @staticmethod
    def _member_hostnames(cluster: Cluster, spec: Dict[str, Any]) -> set:
        return {n.hostname for role in spec["roles"] for n in cluster.nodes_with_role(role)}
