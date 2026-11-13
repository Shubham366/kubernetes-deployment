"""What can be installed, in which versions, on which operating systems, and
what a valid cluster topology looks like for each piece of software.

Everything here is pure data + pure functions so it can be unit-tested without
a cluster.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .exceptions import ValidationError
from .models import Node

# ---------------------------------------------------------------------------
# Technologies (language runtimes / tooling installed per node)
# ---------------------------------------------------------------------------
TECHNOLOGIES: Dict[str, Dict[str, Any]] = {
    "java": {
        "description": "OpenJDK / Eclipse Temurin JDK",
        "playbook": "versions/java.yml",
        "versions": ["8", "11", "17", "21"],
        "default_version": "17",
        "methods": ["package", "tarball"],
        "options": {"java_distribution": ["openjdk", "temurin"], "java_set_default": [True, False]},
    },
    "python": {
        "description": "CPython, from distro packages or built from source",
        "playbook": "versions/python.yml",
        "versions": ["3.8.19", "3.9.19", "3.10.14", "3.11.9", "3.12.4"],
        "default_version": "3.11.9",
        "methods": ["package", "source"],
        "options": {"python_set_default": [True, False]},
    },
    "nodejs": {
        "description": "Node.js from NodeSource or the official tarball",
        "playbook": "versions/nodejs.yml",
        "versions": ["16", "18", "20", "22"],
        "default_version": "20",
        "methods": ["nodesource", "tarball"],
        "options": {},
    },
    "golang": {
        "description": "Go toolchain from the official tarball",
        "playbook": "versions/golang.yml",
        "versions": ["1.21.13", "1.22.5", "1.23.4"],
        "default_version": "1.22.5",
        "methods": ["tarball"],
        "options": {},
    },
    "docker": {
        "description": "Docker Engine from the upstream repository",
        "playbook": "versions/docker.yml",
        "versions": ["latest", "24.0", "25.0", "26.1", "27.0"],
        "default_version": "latest",
        "methods": ["repository"],
        "options": {"docker_users": "list of users added to the docker group"},
    },
}

# JDK majors available as distro packages: (os_family, os_major) -> versions.
# Anything else is installed from the Temurin tarball.
_JAVA_PACKAGES = {
    ("ubuntu", 20): {"8", "11", "17", "21"},
    ("ubuntu", 22): {"8", "11", "17", "21"},
    ("ubuntu", 24): {"8", "11", "17", "21"},
    ("debian", 11): {"11", "17"},
    ("debian", 12): {"17"},
    ("redhat", 7): {"8", "11"},
    ("redhat", 8): {"8", "11", "17", "21"},
    ("redhat", 9): {"8", "11", "17", "21"},
}
# Python minor versions that exist as distro packages.
_PYTHON_PACKAGES = {
    ("ubuntu", 20): {"3.8"},
    ("ubuntu", 22): {"3.10"},
    ("ubuntu", 24): {"3.12"},
    ("debian", 11): {"3.9"},
    ("debian", 12): {"3.11"},
    ("redhat", 7): set(),
    ("redhat", 8): {"3.8", "3.9", "3.11", "3.12"},
    ("redhat", 9): {"3.9", "3.11", "3.12"},
}


def _os_key(node: Node) -> Tuple[str, Optional[int]]:
    family = node.os_type if node.os_type in ("ubuntu", "debian") else node.os_family
    return family, node.os_major


def get_technology(name: str) -> Dict[str, Any]:
    tech = TECHNOLOGIES.get(name)
    if tech is None:
        raise ValidationError("unknown technology %r (available: %s)" % (name, ", ".join(sorted(TECHNOLOGIES))))
    return tech


def validate_technology_version(name: str, version: Optional[str], allow_unlisted: bool = False) -> str:
    tech = get_technology(name)
    version = str(version or tech["default_version"])
    if version in tech["versions"]:
        return version
    if not allow_unlisted:
        raise ValidationError(
            "%s version %r is not in the catalog (%s). Pass allow_unlisted=true to try it anyway."
            % (name, version, ", ".join(tech["versions"]))
        )
    if not re.match(r"^[0-9]+(\.[0-9]+){0,2}$", version):
        raise ValidationError("%s version %r is not a valid version string" % (name, version))
    return version


def resolve_install_method(name: str, version: str, node: Node,
                           requested: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Choose how ``name``/``version`` gets installed on ``node``.

    Returns (method, note). Raises ValidationError when the combination cannot
    work at all, so the request fails before any machine is touched.
    """
    tech = get_technology(name)
    if requested and requested not in tech["methods"]:
        raise ValidationError("%s cannot be installed with method %r (choose from %s)"
                              % (name, requested, ", ".join(tech["methods"])))
    key = _os_key(node)
    major = node.os_major
    note = None

    if name == "java":
        available = _JAVA_PACKAGES.get(key)
        if requested:
            method = requested
        elif available is None:
            # OS version unknown: let the playbook try packages first.
            method, note = "package", "OS version of %s unknown; assuming distro packages" % node.hostname
        elif version in available:
            method = "package"
        else:
            method, note = "tarball", "JDK %s has no package on %s %s; using Temurin tarball" % (
                version, node.os_type, node.os_version)
        if method == "package" and available is not None and version not in available:
            raise ValidationError("JDK %s is not packaged for %s %s (node %s); use method=tarball"
                                  % (version, node.os_type, node.os_version, node.hostname))
        return method, note

    if name == "python":
        minor = ".".join(version.split(".")[:2])
        available = _PYTHON_PACKAGES.get(key, set())
        if requested == "package" and minor not in available and key in _PYTHON_PACKAGES:
            raise ValidationError("Python %s is not packaged for %s %s (node %s); use method=source"
                                  % (minor, node.os_type, node.os_version, node.hostname))
        if requested:
            return requested, None
        if minor in available:
            return "package", None
        if node.os_family == "redhat" and major == 7 and tuple(int(p) for p in minor.split(".")) >= (3, 10):
            note = "EL7 ships OpenSSL 1.0.2; Python >= 3.10 is built against openssl11 from EPEL"
        return "source", note

    if name == "nodejs":
        node_major = int(version.split(".")[0])
        if node.os_family == "redhat" and major == 7 and node_major >= 18:
            raise ValidationError(
                "Node.js %s needs glibc >= 2.28, which EL7 (node %s) does not have; maximum is 16"
                % (version, node.hostname))
        if node.os_type == "ubuntu" and major is not None and major < 20 and node_major >= 20:
            raise ValidationError("Node.js %s is not supported on Ubuntu %s (node %s)"
                                  % (version, node.os_version, node.hostname))
        if requested:
            return requested, None
        # NodeSource dropped old majors and EL7; fall back to the tarball there.
        if node_major < 18 or (node.os_family == "redhat" and major == 7):
            return "tarball", "NodeSource does not serve Node.js %s for %s; using tarball" % (version, node.os_type)
        return "nodesource", None

    if name == "docker":
        if node.os_family == "redhat" and major == 7 and version not in ("latest", "24.0"):
            note = "Docker stopped publishing EL7 packages after 24.x/26.x; newest available will be used"
        return "repository", note

    return requested or tech["methods"][0], None


# ---------------------------------------------------------------------------
# Software (clustered services)
# ---------------------------------------------------------------------------
SOFTWARE: Dict[str, Dict[str, Any]] = {
    "hadoop": {
        "description": "Apache Hadoop (HDFS + YARN), single-NameNode or HA with QJM/ZooKeeper",
        "playbook": "software/hadoop.yml",
        "var_prefix": "hadoop",
        "versions": ["3.4.0", "3.3.6", "3.2.4", "2.10.2"],
        "default_version": "3.3.6",
        "modes": ["standard", "ha"],
        "default_mode": "standard",
        "roles": ["hadoop_namenode", "hadoop_standby_namenode", "hadoop_journalnode", "hadoop_zookeeper",
                  "hadoop_resourcemanager", "hadoop_datanode", "hadoop_historyserver"],
        "actions": ["install", "start", "stop", "restart", "status", "uninstall", "scale_out", "decommission"],
        "scale_roles": ["hadoop_datanode"],
    },
    "redis": {
        "description": "Redis: standalone, master/replica, Sentinel or Redis Cluster",
        "playbook": "software/redis.yml",
        "var_prefix": "redis",
        "versions": ["7.2.5", "7.0.15", "6.2.14"],
        "default_version": "7.2.5",
        "modes": ["standalone", "replication", "sentinel", "cluster"],
        "default_mode": "standalone",
        "roles": ["redis_master", "redis_replica", "redis_sentinel", "redis_cluster"],
        "actions": ["install", "start", "stop", "restart", "status", "uninstall", "scale_out"],
        "scale_roles": ["redis_replica", "redis_cluster"],
    },
    "postgresql": {
        "description": "PostgreSQL from PGDG: standalone or streaming replication",
        "playbook": "software/postgresql.yml",
        "var_prefix": "postgresql",
        "versions": ["16", "15", "14", "13", "12"],
        "default_version": "16",
        "modes": ["standalone", "replication"],
        "default_mode": "standalone",
        "roles": ["postgresql_primary", "postgresql_replica"],
        "actions": ["install", "start", "stop", "restart", "status", "uninstall", "add_replica", "promote"],
        "scale_roles": ["postgresql_replica"],
    },
}


def get_software(name: str) -> Dict[str, Any]:
    software = SOFTWARE.get(name)
    if software is None:
        raise ValidationError("unknown software %r (available: %s)" % (name, ", ".join(sorted(SOFTWARE))))
    return software


def hadoop_java_version(hadoop_version: str, requested: Optional[Any] = None) -> str:
    """Hadoop 3.3+ runs on Java 8 or 11; older lines only on Java 8."""
    parts = tuple(int(p) for p in hadoop_version.split(".")[:2])
    supported = ["8", "11"] if parts >= (3, 3) else ["8"]
    if requested is None:
        return supported[-1]
    requested = str(requested)
    if requested not in supported:
        raise ValidationError("Hadoop %s supports Java %s, not %s"
                              % (hadoop_version, " or ".join(supported), requested))
    return requested


def auto_assign_roles(software: str, mode: str, nodes: List[Node], options: Dict[str, Any]) -> Dict[str, List[str]]:
    """Propose a role layout when the caller did not supply one. Deterministic
    (nodes are taken in hostname order) so re-running gives the same layout."""
    names = [n.hostname for n in sorted(nodes, key=lambda n: n.hostname)]
    count = len(names)
    if count == 0:
        raise ValidationError("no nodes available to deploy %s" % software)

    if software == "hadoop":
        if mode == "ha":
            if count < 3:
                raise ValidationError("Hadoop HA needs at least 3 nodes (got %d)" % count)
            quorum = names[:3]
            return {
                "hadoop_namenode": [names[0]],
                "hadoop_standby_namenode": [names[1]],
                "hadoop_journalnode": quorum,
                "hadoop_zookeeper": quorum,
                "hadoop_resourcemanager": names[:2],
                "hadoop_historyserver": [names[2]],
                # small clusters co-locate DataNodes with the masters
                "hadoop_datanode": names[2:] if count >= 6 else names,
            }
        return {
            "hadoop_namenode": [names[0]],
            "hadoop_resourcemanager": [names[0]],
            "hadoop_historyserver": [names[0]],
            "hadoop_datanode": names[1:] if count > 1 else names,
        }

    if software == "redis":
        if mode == "standalone":
            return {"redis_master": [names[0]]}
        if mode == "replication":
            if count < 2:
                raise ValidationError("Redis replication needs at least 2 nodes")
            return {"redis_master": [names[0]], "redis_replica": names[1:]}
        if mode == "sentinel":
            if count < 3:
                raise ValidationError("Redis Sentinel needs at least 3 nodes")
            return {"redis_master": [names[0]], "redis_replica": names[1:], "redis_sentinel": names[:3]}
        return {"redis_cluster": names}

    if software == "postgresql":
        if mode == "standalone":
            return {"postgresql_primary": [names[0]]}
        if count < 2:
            raise ValidationError("PostgreSQL replication needs at least 2 nodes")
        return {"postgresql_primary": [names[0]], "postgresql_replica": names[1:]}

    raise ValidationError("no automatic role layout for %s" % software)


def _need(assignment: Dict[str, List[Node]], role: str, exactly: Optional[int] = None,
          at_least: Optional[int] = None, at_most: Optional[int] = None, odd: bool = False) -> int:
    n = len(assignment.get(role, []))
    if exactly is not None and n != exactly:
        raise ValidationError("role %s needs exactly %d node(s), got %d" % (role, exactly, n))
    if at_least is not None and n < at_least:
        raise ValidationError("role %s needs at least %d node(s), got %d" % (role, at_least, n))
    if at_most is not None and n > at_most:
        raise ValidationError("role %s allows at most %d node(s), got %d" % (role, at_most, n))
    if odd and n % 2 == 0:
        raise ValidationError("role %s needs an odd number of nodes for quorum, got %d" % (role, n))
    return n


def validate_topology(software: str, mode: str, version: str, assignment: Dict[str, List[Node]],
                      options: Dict[str, Any]) -> List[str]:
    """Reject layouts that cannot work; return warnings for ones that work
    but are fragile."""
    spec = get_software(software)
    if mode not in spec["modes"]:
        raise ValidationError("%s mode must be one of %s, got %r" % (software, ", ".join(spec["modes"]), mode))
    unknown = sorted(set(assignment) - set(spec["roles"]))
    if unknown:
        raise ValidationError("unknown %s role(s): %s (valid: %s)"
                              % (software, ", ".join(unknown), ", ".join(spec["roles"])))
    warnings: List[str] = []
    every = {n.hostname: n for nodes in assignment.values() for n in nodes}

    if software == "hadoop":
        _need(assignment, "hadoop_namenode", exactly=1)
        datanodes = _need(assignment, "hadoop_datanode", at_least=1)
        _need(assignment, "hadoop_historyserver", at_most=1)
        if mode == "ha":
            _need(assignment, "hadoop_standby_namenode", exactly=1)
            _need(assignment, "hadoop_journalnode", at_least=3, odd=True)
            _need(assignment, "hadoop_zookeeper", at_least=3, odd=True)
            _need(assignment, "hadoop_resourcemanager", at_least=1, at_most=2)
            if assignment["hadoop_namenode"][0].hostname == assignment["hadoop_standby_namenode"][0].hostname:
                raise ValidationError("active and standby NameNode must be on different nodes")
        else:
            for role in ("hadoop_standby_namenode", "hadoop_journalnode", "hadoop_zookeeper"):
                if assignment.get(role):
                    raise ValidationError("role %s is only valid with mode=ha" % role)
            _need(assignment, "hadoop_resourcemanager", exactly=1)
            warnings.append("standard mode has a single NameNode: HDFS is unavailable while it is down")
        replication = int(options.get("hadoop_replication_factor", 3))
        if replication < 1:
            raise ValidationError("hadoop_replication_factor must be >= 1")
        if replication > datanodes:
            raise ValidationError(
                "hadoop_replication_factor=%d but only %d DataNode(s): blocks could never be fully replicated"
                % (replication, datanodes))
        if datanodes < 3:
            warnings.append("fewer than 3 DataNodes: losing one node risks data loss")

    elif software == "redis":
        if mode == "cluster":
            for role in ("redis_master", "redis_replica", "redis_sentinel"):
                if assignment.get(role):
                    raise ValidationError("role %s is not used with mode=cluster; use redis_cluster" % role)
            replicas = int(options.get("redis_cluster_replicas", 1))
            if replicas < 0:
                raise ValidationError("redis_cluster_replicas must be >= 0")
            required = 3 * (1 + replicas)
            _need(assignment, "redis_cluster", at_least=required)
            if replicas == 0:
                warnings.append("redis_cluster_replicas=0: any node failure loses its hash slots")
        else:
            if assignment.get("redis_cluster"):
                raise ValidationError("role redis_cluster is only valid with mode=cluster")
            _need(assignment, "redis_master", exactly=1)
            if mode == "standalone":
                _need(assignment, "redis_replica", at_most=0)
                _need(assignment, "redis_sentinel", at_most=0)
            else:
                replicas = _need(assignment, "redis_replica", at_least=1)
                master = assignment["redis_master"][0].hostname
                if master in [n.hostname for n in assignment["redis_replica"]]:
                    raise ValidationError("node %s cannot be both redis_master and redis_replica" % master)
                if mode == "sentinel":
                    sentinels = _need(assignment, "redis_sentinel", at_least=3, odd=True)
                    quorum = options.get("redis_sentinel_quorum")
                    if quorum is not None and not 1 <= int(quorum) <= sentinels:
                        raise ValidationError("redis_sentinel_quorum must be between 1 and %d" % sentinels)
                    if replicas < 2:
                        warnings.append("only one replica: after a failover there is no redundancy left")
                else:
                    _need(assignment, "redis_sentinel", at_most=0)
                    warnings.append("replication without Sentinel has no automatic failover")

    elif software == "postgresql":
        _need(assignment, "postgresql_primary", exactly=1)
        primary = assignment["postgresql_primary"][0].hostname
        if mode == "standalone":
            _need(assignment, "postgresql_replica", at_most=0)
        else:
            replicas = _need(assignment, "postgresql_replica", at_least=1)
            if primary in [n.hostname for n in assignment["postgresql_replica"]]:
                raise ValidationError("node %s cannot be both primary and replica" % primary)
            if options.get("postgresql_synchronous_replication") and replicas < 2:
                warnings.append("synchronous replication with one replica: writes block whenever it is down")
        major = int(str(version).split(".")[0])
        for node in every.values():
            if node.os_family == "redhat" and node.os_major == 7 and major >= 16:
                raise ValidationError("PGDG does not publish PostgreSQL %s for EL7 (node %s); maximum is 15"
                                      % (version, node.hostname))

    families = {n.os_family for n in every.values()}
    if len(families) > 1:
        warnings.append("deployment mixes OS families (%s); keep versions and paths in mind when operating it"
                        % ", ".join(sorted(families)))
    return warnings
