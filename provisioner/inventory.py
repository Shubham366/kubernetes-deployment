"""Generates Ansible inventories from the cluster model.

The inventory is written as JSON (which the Ansible ``yaml`` inventory plugin
accepts for ``.json`` files), so no YAML library is needed.

Groups produced for every cluster:
  * one group per node role, named exactly like the role (``hadoop_namenode``,
    ``redis_master``, ``postgresql_primary`` ...) - the software playbooks
    target these;
  * ``os_<type>`` (os_ubuntu, os_centos, os_rhel ...) and ``family_<family>``;
  * ``label_<key>_<value>`` for every node label.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .config import Settings
from .models import Cluster, Node

_GROUP_SAFE = re.compile(r"[^A-Za-z0-9_]")


def _group_name(raw: str) -> str:
    return _GROUP_SAFE.sub("_", raw).lower()


class InventoryBuilder:
    def __init__(self, settings: Settings):
        self.settings = settings

    def host_vars(self, node: Node) -> Dict[str, Any]:
        hv: Dict[str, Any] = {
            "ansible_host": node.address,
            "ansible_user": node.ssh_user or self.settings.default_ssh_user,
            "ansible_port": node.ssh_port or self.settings.default_ssh_port,
            "ansible_become": bool(node.become),
            "node_id": node.id,
            "node_roles": list(node.roles),
            "node_labels": dict(node.labels),
            "declared_os": node.os_type,
            "declared_os_version": node.os_version,
        }
        key = node.ssh_key_path or self.settings.default_ssh_key_path
        if key:
            hv["ansible_ssh_private_key_file"] = os.path.expanduser(key)
        # EL7 ships python2 only; let Ansible discover instead of assuming python3.
        if node.os_family == "redhat" and node.os_major == 7:
            hv["ansible_python_interpreter"] = "auto_legacy_silent"
        return hv

    def build(self, cluster: Cluster, nodes: Optional[Iterable[Node]] = None,
              extra_groups: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
        """Return the inventory structure. ``nodes`` restricts the hosts that
        are included; by default every non-decommissioned node is.
        ``extra_groups`` ({group: [hostnames]}) adds memberships that are not
        (yet) stored on the nodes - used for dry runs of a role layout."""
        selected: List[Node] = list(nodes) if nodes is not None else cluster.active_nodes()
        hosts: Dict[str, Any] = {}
        children: Dict[str, Dict[str, Any]] = {}

        def add(group: str, hostname: str) -> None:
            children.setdefault(group, {"hosts": {}})["hosts"][hostname] = {}

        for node in selected:
            hosts[node.hostname] = self.host_vars(node)
            add("os_" + _group_name(node.os_type), node.hostname)
            add("family_" + node.os_family, node.hostname)
            for role in node.roles:
                add(_group_name(role), node.hostname)
            for key, value in node.labels.items():
                add("label_%s_%s" % (_group_name(key), _group_name(value)), node.hostname)

        for group, members in (extra_groups or {}).items():
            for hostname in members:
                if hostname in hosts:
                    add(_group_name(group), hostname)

        return {
            "all": {
                "hosts": hosts,
                "children": children,
                "vars": {
                    "provisioner_cluster_id": cluster.id,
                    "provisioner_cluster_name": cluster.name,
                    "provisioner_environment": cluster.environment,
                },
            }
        }

    def write(self, cluster: Cluster, tag: str, nodes: Optional[Iterable[Node]] = None,
              extra_groups: Optional[Dict[str, List[str]]] = None) -> Path:
        inventory = self.build(cluster, nodes, extra_groups)
        path = self.settings.inventory_dir / ("%s-%s.json" % (cluster.name, tag))
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(inventory, indent=2, sort_keys=True))
        os.replace(str(tmp), str(path))
        return path

    @staticmethod
    def hosts_in(inventory_path: Path, limit: Optional[List[str]] = None) -> List[str]:
        data = json.loads(Path(inventory_path).read_text())
        hosts = sorted(data.get("all", {}).get("hosts", {}))
        if limit:
            wanted = set(limit)
            hosts = [h for h in hosts if h in wanted]
        return hosts
