"""Technology version management: install, upgrade/downgrade and remove
language runtimes and tooling (Java, Python, Node.js, Go, Docker) on any subset
of a cluster's nodes.

A cluster can mix Ubuntu, CentOS and RHEL nodes, and the right install method
differs per OS (distro package vs. tarball vs. source build). The controller
resolves the method per node up front, then runs one playbook step per method
so each group of nodes gets the variables that fit it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..catalog import TECHNOLOGIES, get_technology, resolve_install_method, validate_technology_version
from ..exceptions import ConflictError, ValidationError
from ..executor import PlaybookResult
from ..jobs import Step
from ..models import Job, Node
from .base import BaseController

# Technologies other deployed software depends on: {technology: {software: role prefix}}
_DEPENDENTS = {"java": {"hadoop": "hadoop_"}}


class VersionController(BaseController):
    kind = "version"

    def catalog(self) -> Dict[str, Any]:
        return {
            name: {k: v for k, v in tech.items() if k != "playbook"}
            for name, tech in sorted(TECHNOLOGIES.items())
        }

    def list_installed(self, ref: str) -> List[Dict[str, Any]]:
        cluster = self.cluster(ref)
        return self.store.list_installations(cluster.id, "technology")

    # ------------------------------------------------------------------
    def install(self, ref: str, body: Dict[str, Any]) -> Job:
        """Install or switch a technology version. ``body``::

            {"technology": "java", "version": "17", "nodes": ["n1", "n2"],
             "method": "tarball", "allow_unlisted": false,
             "options": {"java_distribution": "temurin", "java_set_default": true}}

        Omitting ``nodes`` targets every active node; omitting ``method`` lets
        the catalog decide per node.
        """
        cluster = self.cluster(ref)
        name = str(self.require(body, "technology")).lower()
        tech = get_technology(name)
        version = validate_technology_version(name, body.get("version"), self.as_bool(body.get("allow_unlisted")))
        targets = cluster.resolve_nodes(body.get("nodes"))
        if not targets:
            raise ValidationError("cluster %s has no active nodes" % cluster.name)
        options = self._options(name, body.get("options"))

        # Resolve the method for every node before touching anything, so an
        # impossible combination on node 7 does not leave nodes 1-6 changed.
        by_method: Dict[str, List[Node]] = {}
        notes: List[str] = []
        for node in targets:
            method, note = resolve_install_method(name, version, node, body.get("method"))
            by_method.setdefault(method, []).append(node)
            if note and note not in notes:
                notes.append(note)

        existing = {i["hostname"]: i for i in self.store.list_installations(cluster.id, "technology", name)}
        changes = []
        for node in targets:
            previous = existing.get(node.hostname)
            if previous and previous["state"] == "installed" and previous["version"] != version:
                changes.append({"hostname": node.hostname, "from": previous["version"], "to": version})

        steps = []
        for method in sorted(by_method):
            hosts = [n.hostname for n in by_method[method]]
            extra = {
                "%s_version" % name: version,
                "%s_state" % name: "present",
                "%s_install_method" % name: method,
            }
            extra.update(options)
            steps.append(Step("%s %s via %s (%d node(s))" % (name, version, method, len(hosts)),
                              tech["playbook"], extra, limit=hosts, continue_on_failure=True))

        params = {"technology": name, "version": version, "nodes": [n.hostname for n in targets],
                  "methods": {m: [n.hostname for n in ns] for m, ns in by_method.items()},
                  "options": options, "version_changes": changes, "notes": notes}
        dry_run = self.as_bool(body.get("dry_run"))

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            return self._record(job, results, cluster.id, name, version, "installed", params)

        job = self.submit(cluster, "install", steps, params=params, finalize=finalize, dry_run=dry_run)
        if not job.dry_run:
            for node in targets:
                self.store.upsert_installation(cluster.id, node.hostname, "technology", name, version,
                                               "installing", {"previous": existing.get(node.hostname, {}).get("version")},
                                               job.id)
        return job

    def uninstall(self, ref: str, body: Dict[str, Any]) -> Job:
        cluster = self.cluster(ref)
        name = str(self.require(body, "technology")).lower()
        tech = get_technology(name)
        targets = cluster.resolve_nodes(body.get("nodes"))
        force = self.as_bool(body.get("force"))

        # Refuse to pull a runtime out from under software that needs it.
        for software, prefix in _DEPENDENTS.get(name, {}).items():
            deployed = self.store.get_installation(cluster.id, "software", software)
            if deployed and deployed["state"] in ("installed", "installing") and not force:
                blocked = [n.hostname for n in targets if any(r.startswith(prefix) for r in n.roles)]
                if blocked:
                    raise ConflictError(
                        "%s is required by %s on: %s. Uninstall %s first or pass force=true."
                        % (name, software, ", ".join(blocked), software))

        existing = {i["hostname"]: i for i in self.store.list_installations(cluster.id, "technology", name)}
        version = str(body.get("version") or "")
        steps = []
        # The playbook needs the version to know which package/dir to remove;
        # nodes may hold different versions, so group by recorded version.
        groups: Dict[str, List[str]] = {}
        for node in targets:
            node_version = version or existing.get(node.hostname, {}).get("version") or tech["default_version"]
            groups.setdefault(str(node_version), []).append(node.hostname)
        for node_version, hosts in sorted(groups.items()):
            extra = {"%s_version" % name: node_version, "%s_state" % name: "absent"}
            steps.append(Step("remove %s %s (%d node(s))" % (name, node_version, len(hosts)),
                              tech["playbook"], extra, limit=hosts, continue_on_failure=True))

        params = {"technology": name, "nodes": [n.hostname for n in targets], "versions": groups}

        def finalize(job: Job, results: List[PlaybookResult]) -> Dict[str, Any]:
            return self._record(job, results, cluster.id, name, version, "removed", params)

        return self.submit(cluster, "uninstall", steps, params=params, finalize=finalize,
                           dry_run=self.as_bool(body.get("dry_run")))

    # ------------------------------------------------------------------
    @staticmethod
    def _options(name: str, raw: Any) -> Dict[str, Any]:
        """Only variables namespaced to the technology may be passed through,
        and never the ones the controller owns."""
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            raise ValidationError("options must be an object")
        reserved = {"%s_version" % name, "%s_state" % name, "%s_install_method" % name}
        clean = {}
        for key, value in raw.items():
            if not str(key).startswith(name + "_"):
                raise ValidationError("option %r must start with %r" % (key, name + "_"))
            if key in reserved:
                raise ValidationError("option %r is set by the controller; use the top-level field" % key)
            clean[str(key)] = value
        return clean

    def _record(self, job: Job, results: List[PlaybookResult], cluster_id: str, name: str, version: str,
                final_state: str, params: Dict[str, Any]) -> Dict[str, Any]:
        succeeded, failed, unreachable = [], [], []
        for result in results:
            succeeded += result.ok_hosts
            failed += result.failed_hosts
            unreachable += result.unreachable_hosts
        not_attempted = sorted(set(params["nodes"]) - set(succeeded) - set(failed) - set(unreachable))
        outcome: Dict[str, Any] = {
            "technology": name, "version": version, "succeeded": sorted(succeeded), "failed": sorted(failed),
            "unreachable": sorted(unreachable), "not_attempted": not_attempted,
            "notes": params.get("notes", []), "simulated": job.dry_run,
        }
        if job.dry_run:
            return outcome
        existing = {i["hostname"]: i for i in self.store.list_installations(cluster_id, "technology", name)}
        for hostname in params["nodes"]:
            current = existing.get(hostname, {})
            if hostname in succeeded:
                recorded = version or current.get("version", "")
                self.store.upsert_installation(cluster_id, hostname, "technology", name, recorded, final_state,
                                               current.get("params"), job.id)
            elif final_state == "installed":
                # Failed/unreached install: the node's real state is unknown.
                self.store.upsert_installation(cluster_id, hostname, "technology", name,
                                               current.get("version", version), "failed",
                                               current.get("params"), job.id)
        return outcome
