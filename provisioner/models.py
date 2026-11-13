"""Domain objects: clusters, nodes and jobs, plus input validation."""
from __future__ import annotations

import ipaddress
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .exceptions import ValidationError

# Supported distributions and the Ansible os_family each belongs to.
OS_FAMILIES = {
    "ubuntu": "debian",
    "debian": "debian",
    "centos": "redhat",
    "rhel": "redhat",
    "rocky": "redhat",
    "almalinux": "redhat",
    "oracle": "redhat",
}

# ansible_distribution -> our os_type
DISTRIBUTION_MAP = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "redhat": "rhel",
    "rocky": "rocky",
    "almalinux": "almalinux",
    "oraclelinux": "oracle",
}

NODE_STATES = ("registered", "reachable", "unreachable", "bootstrapped", "decommissioned")
CLUSTER_STATES = ("new", "ready", "degraded", "busy", "deleting")

JOB_PENDING = "pending"
JOB_RUNNING = "running"
JOB_SUCCESS = "success"
JOB_FAILED = "failed"
JOB_PARTIAL = "partial"       # some hosts failed, others succeeded
JOB_CANCELLED = "cancelled"
JOB_INTERRUPTED = "interrupted"  # backend restarted while the job was running
JOB_TERMINAL = (JOB_SUCCESS, JOB_FAILED, JOB_PARTIAL, JOB_CANCELLED, JOB_INTERRUPTED)

_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{1,62}$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9_]{1,62}$")
_SECRET_KEY_RE = re.compile(r"(password|passwd|secret|token|private_key)", re.I)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def mask_secrets(value: Any) -> Any:
    """Recursively replace values of secret-looking keys so they never reach
    API responses, job records or logs."""
    if isinstance(value, dict):
        return {
            k: ("***" if _SECRET_KEY_RE.search(str(k)) and v not in (None, "") else mask_secrets(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [mask_secrets(v) for v in value]
    return value


def validate_name(name: Any, what: str = "name") -> str:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise ValidationError(
            "%s must start with a letter and contain only letters, digits, '-' or '_' (2-63 chars): %r" % (what, name)
        )
    return name


def validate_address(address: Any) -> str:
    if not isinstance(address, str) or not address:
        raise ValidationError("node address is required")
    try:
        ipaddress.ip_address(address)
        return address
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(address):
        raise ValidationError("node address is neither an IP nor a valid DNS name: %r" % address)
    return address


def validate_roles(roles: Any) -> List[str]:
    if roles is None:
        return []
    if not isinstance(roles, list):
        raise ValidationError("roles must be a list")
    for role in roles:
        if not isinstance(role, str) or not _ROLE_RE.match(role):
            raise ValidationError("invalid role name: %r" % (role,))
    return sorted(set(roles))


@dataclass
class Node:
    hostname: str
    address: str
    os_type: str = "ubuntu"
    os_version: str = ""
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_key_path: str = ""
    become: bool = True
    roles: List[str] = field(default_factory=list)
    labels: Dict[str, str] = field(default_factory=dict)
    state: str = "registered"
    facts: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=new_id)
    cluster_id: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    @property
    def os_family(self) -> str:
        return OS_FAMILIES.get(self.os_type, "unknown")

    @property
    def os_major(self) -> Optional[int]:
        match = re.match(r"(\d+)", self.os_version or "")
        return int(match.group(1)) if match else None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["os_family"] = self.os_family
        return data

    @classmethod
    def from_spec(cls, spec: Dict[str, Any], defaults: Optional[Dict[str, Any]] = None) -> "Node":
        """Build a node from user input, applying cluster-level defaults."""
        if not isinstance(spec, dict):
            raise ValidationError("each node must be an object")
        merged = dict(defaults or {})
        merged.update({k: v for k, v in spec.items() if v is not None})

        hostname = merged.get("hostname")
        if not isinstance(hostname, str) or not _HOSTNAME_RE.match(hostname):
            raise ValidationError("invalid node hostname: %r" % (hostname,))
        os_type = str(merged.get("os_type", "ubuntu")).lower()
        if os_type in ("redhat", "red hat", "rhel"):
            os_type = "rhel"
        if os_type not in OS_FAMILIES:
            raise ValidationError(
                "unsupported os_type %r for node %s (supported: %s)" % (os_type, hostname, ", ".join(sorted(OS_FAMILIES)))
            )
        try:
            port = int(merged.get("ssh_port", 22))
        except (TypeError, ValueError):
            raise ValidationError("ssh_port must be an integer for node %s" % hostname)
        if not 1 <= port <= 65535:
            raise ValidationError("ssh_port out of range for node %s" % hostname)
        labels = merged.get("labels") or {}
        if not isinstance(labels, dict):
            raise ValidationError("labels must be an object for node %s" % hostname)

        return cls(
            hostname=hostname,
            address=validate_address(merged.get("address") or hostname),
            os_type=os_type,
            os_version=str(merged.get("os_version", "") or ""),
            ssh_user=str(merged.get("ssh_user") or "root"),
            ssh_port=port,
            ssh_key_path=str(merged.get("ssh_key_path") or ""),
            become=bool(merged.get("become", True)),
            roles=validate_roles(merged.get("roles")),
            labels={str(k): str(v) for k, v in labels.items()},
        )


@dataclass
class Cluster:
    name: str
    description: str = ""
    environment: str = "dev"
    state: str = "new"
    nodes: List[Node] = field(default_factory=list)
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self, with_nodes: bool = True) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "environment": self.environment,
            "state": self.state,
            "node_count": len(self.nodes),
            "os_breakdown": self.os_breakdown(),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if with_nodes:
            data["nodes"] = [n.to_dict() for n in self.nodes]
        return data

    def os_breakdown(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for node in self.nodes:
            out[node.os_type] = out.get(node.os_type, 0) + 1
        return out

    def active_nodes(self) -> List[Node]:
        return [n for n in self.nodes if n.state != "decommissioned"]

    def find_node(self, ref: str) -> Optional[Node]:
        for node in self.nodes:
            if ref in (node.id, node.hostname, node.address):
                return node
        return None

    def resolve_nodes(self, refs: Optional[List[str]]) -> List[Node]:
        """Turn hostnames/ids/addresses into nodes. ``None`` or empty means all
        active nodes."""
        if not refs:
            return self.active_nodes()
        if not isinstance(refs, list):
            raise ValidationError("nodes must be a list of hostnames or ids")
        found, missing = [], []
        for ref in refs:
            node = self.find_node(str(ref))
            if node is None:
                missing.append(str(ref))
            elif node not in found:
                found.append(node)
        if missing:
            raise ValidationError("unknown node(s) in cluster %s: %s" % (self.name, ", ".join(missing)))
        decommissioned = [n.hostname for n in found if n.state == "decommissioned"]
        if decommissioned:
            raise ValidationError("node(s) are decommissioned: %s" % ", ".join(decommissioned))
        return found

    def nodes_with_role(self, role: str) -> List[Node]:
        return [n for n in self.active_nodes() if role in n.roles]


@dataclass
class Job:
    cluster_id: str
    kind: str            # cluster | version | software | scan | patch
    action: str
    params: Dict[str, Any] = field(default_factory=dict)
    status: str = JOB_PENDING
    dry_run: bool = False
    steps: List[Dict[str, Any]] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    log_path: str = ""
    id: str = field(default_factory=new_id)
    created_at: str = field(default_factory=now_iso)
    started_at: str = ""
    finished_at: str = ""

    @property
    def finished(self) -> bool:
        return self.status in JOB_TERMINAL

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["params"] = mask_secrets(self.params)
        return data
