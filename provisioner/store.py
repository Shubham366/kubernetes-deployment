"""SQLite persistence for clusters, nodes, jobs, scan/patch results and the
record of what is installed where."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .exceptions import ConflictError, NotFoundError
from .models import JOB_INTERRUPTED, JOB_PENDING, JOB_RUNNING, Cluster, Job, Node, now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS clusters (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    environment TEXT NOT NULL DEFAULT 'dev',
    state TEXT NOT NULL DEFAULT 'new',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    address TEXT NOT NULL,
    os_type TEXT NOT NULL,
    os_version TEXT NOT NULL DEFAULT '',
    ssh_user TEXT NOT NULL,
    ssh_port INTEGER NOT NULL,
    ssh_key_path TEXT NOT NULL DEFAULT '',
    become INTEGER NOT NULL DEFAULT 1,
    roles TEXT NOT NULL DEFAULT '[]',
    labels TEXT NOT NULL DEFAULT '{}',
    state TEXT NOT NULL DEFAULT 'registered',
    facts TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (cluster_id, hostname)
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    cluster_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 0,
    params TEXT NOT NULL DEFAULT '{}',
    steps TEXT NOT NULL DEFAULT '[]',
    result TEXT NOT NULL DEFAULT '{}',
    error TEXT NOT NULL DEFAULT '',
    log_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_cluster ON jobs (cluster_id, kind, created_at);
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    status TEXT NOT NULL,
    updates_available INTEGER NOT NULL DEFAULT 0,
    security_updates INTEGER NOT NULL DEFAULT 0,
    compliance_failed INTEGER NOT NULL DEFAULT 0,
    reboot_required INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    report TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY (scan_id, hostname)
);
CREATE TABLE IF NOT EXISTS patch_results (
    patch_id TEXT NOT NULL,
    cluster_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    status TEXT NOT NULL,
    packages_updated INTEGER NOT NULL DEFAULT 0,
    rebooted INTEGER NOT NULL DEFAULT 0,
    report TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY (patch_id, hostname)
);
CREATE TABLE IF NOT EXISTS installations (
    cluster_id TEXT NOT NULL,
    hostname TEXT NOT NULL,          -- '' for cluster-wide software deployments
    category TEXT NOT NULL,          -- technology | software
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    state TEXT NOT NULL,             -- installing | installed | failed | removed
    params TEXT NOT NULL DEFAULT '{}',
    job_id TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (cluster_id, hostname, category, name)
);
"""


class Store:
    def __init__(self, db_path: Path):
        self._path = str(db_path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def _query(self, sql: str, args: tuple = ()) -> List[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    # ------------------------------------------------------------ clusters
    @staticmethod
    def _node_from_row(row: sqlite3.Row) -> Node:
        return Node(
            id=row["id"], cluster_id=row["cluster_id"], hostname=row["hostname"], address=row["address"],
            os_type=row["os_type"], os_version=row["os_version"], ssh_user=row["ssh_user"],
            ssh_port=row["ssh_port"], ssh_key_path=row["ssh_key_path"], become=bool(row["become"]),
            roles=json.loads(row["roles"]), labels=json.loads(row["labels"]), state=row["state"],
            facts=json.loads(row["facts"]), created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def _cluster_from_row(self, row: sqlite3.Row) -> Cluster:
        nodes = [self._node_from_row(r) for r in self._query(
            "SELECT * FROM nodes WHERE cluster_id = ? ORDER BY hostname", (row["id"],))]
        return Cluster(
            id=row["id"], name=row["name"], description=row["description"], environment=row["environment"],
            state=row["state"], nodes=nodes, created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def create_cluster(self, cluster: Cluster) -> Cluster:
        try:
            with self._tx() as conn:
                conn.execute(
                    "INSERT INTO clusters (id, name, description, environment, state, created_at, updated_at)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (cluster.id, cluster.name, cluster.description, cluster.environment, cluster.state,
                     cluster.created_at, cluster.updated_at),
                )
                for node in cluster.nodes:
                    node.cluster_id = cluster.id
                    self._insert_node(conn, node)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("cluster or node already exists: %s" % exc)
        return cluster

    def get_cluster(self, ref: str) -> Cluster:
        rows = self._query("SELECT * FROM clusters WHERE id = ? OR name = ?", (ref, ref))
        if not rows:
            raise NotFoundError("cluster not found: %s" % ref)
        return self._cluster_from_row(rows[0])

    def list_clusters(self) -> List[Cluster]:
        return [self._cluster_from_row(r) for r in self._query("SELECT * FROM clusters ORDER BY name")]

    def update_cluster(self, cluster_id: str, **changes: Any) -> None:
        allowed = {"description", "environment", "state"}
        sets = {k: v for k, v in changes.items() if k in allowed}
        sets["updated_at"] = now_iso()
        sql = "UPDATE clusters SET %s WHERE id = ?" % ", ".join("%s = ?" % k for k in sets)
        with self._tx() as conn:
            conn.execute(sql, tuple(sets.values()) + (cluster_id,))

    def delete_cluster(self, cluster_id: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM clusters WHERE id = ?", (cluster_id,))
            for table in ("installations", "scan_results", "patch_results"):
                conn.execute("DELETE FROM %s WHERE cluster_id = ?" % table, (cluster_id,))

    # --------------------------------------------------------------- nodes
    @staticmethod
    def _insert_node(conn: sqlite3.Connection, node: Node) -> None:
        conn.execute(
            "INSERT INTO nodes (id, cluster_id, hostname, address, os_type, os_version, ssh_user, ssh_port,"
            " ssh_key_path, become, roles, labels, state, facts, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (node.id, node.cluster_id, node.hostname, node.address, node.os_type, node.os_version,
             node.ssh_user, node.ssh_port, node.ssh_key_path, int(node.become), json.dumps(node.roles),
             json.dumps(node.labels), node.state, json.dumps(node.facts), node.created_at, node.updated_at),
        )

    def add_nodes(self, cluster_id: str, nodes: List[Node]) -> None:
        try:
            with self._tx() as conn:
                for node in nodes:
                    node.cluster_id = cluster_id
                    self._insert_node(conn, node)
        except sqlite3.IntegrityError:
            raise ConflictError("a node with the same hostname already exists in this cluster")

    def save_node(self, node: Node) -> None:
        node.updated_at = now_iso()
        with self._tx() as conn:
            conn.execute(
                "UPDATE nodes SET address=?, os_type=?, os_version=?, ssh_user=?, ssh_port=?, ssh_key_path=?,"
                " become=?, roles=?, labels=?, state=?, facts=?, updated_at=? WHERE id=?",
                (node.address, node.os_type, node.os_version, node.ssh_user, node.ssh_port, node.ssh_key_path,
                 int(node.become), json.dumps(node.roles), json.dumps(node.labels), node.state,
                 json.dumps(node.facts), node.updated_at, node.id),
            )

    def delete_node(self, node_id: str) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))

    # ---------------------------------------------------------------- jobs
    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> Job:
        return Job(
            id=row["id"], cluster_id=row["cluster_id"], kind=row["kind"], action=row["action"],
            status=row["status"], dry_run=bool(row["dry_run"]), params=json.loads(row["params"]),
            steps=json.loads(row["steps"]), result=json.loads(row["result"]), error=row["error"],
            log_path=row["log_path"], created_at=row["created_at"], started_at=row["started_at"],
            finished_at=row["finished_at"],
        )

    def save_job(self, job: Job) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO jobs (id, cluster_id, kind, action, status, dry_run, params, steps, result, error,"
                " log_path, created_at, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET status=excluded.status, steps=excluded.steps,"
                " result=excluded.result, error=excluded.error, log_path=excluded.log_path,"
                " started_at=excluded.started_at, finished_at=excluded.finished_at",
                (job.id, job.cluster_id, job.kind, job.action, job.status, int(job.dry_run),
                 json.dumps(job.params), json.dumps(job.steps), json.dumps(job.result), job.error,
                 job.log_path, job.created_at, job.started_at, job.finished_at),
            )

    def get_job(self, job_id: str) -> Job:
        rows = self._query("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not rows:
            raise NotFoundError("job not found: %s" % job_id)
        return self._job_from_row(rows[0])

    def list_jobs(self, cluster_id: Optional[str] = None, kind: Optional[str] = None,
                  status: Optional[str] = None, action: Optional[str] = None, limit: int = 50) -> List[Job]:
        clauses, args = [], []  # type: List[str], List[Any]
        for column, value in (("cluster_id", cluster_id), ("kind", kind), ("status", status), ("action", action)):
            if value:
                clauses.append("%s = ?" % column)
                args.append(value)
        sql = "SELECT * FROM jobs"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        args.append(max(1, min(int(limit), 500)))
        return [self._job_from_row(r) for r in self._query(sql, tuple(args))]

    def mark_stale_jobs_interrupted(self) -> int:
        """Jobs left pending/running by a previous process can never finish."""
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE jobs SET status = ?, error = ?, finished_at = ? WHERE status IN (?, ?)",
                (JOB_INTERRUPTED, "backend restarted while the job was in flight", now_iso(),
                 JOB_PENDING, JOB_RUNNING),
            )
            return cur.rowcount

    # ------------------------------------------------------- scan results
    def save_scan_result(self, scan_id: str, cluster_id: str, hostname: str, status: str,
                         summary: Dict[str, Any], report: Dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scan_results (scan_id, cluster_id, hostname, status, updates_available,"
                " security_updates, compliance_failed, reboot_required, risk_score, report, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, cluster_id, hostname, status, int(summary.get("updates_available", 0)),
                 int(summary.get("security_updates", 0)), int(summary.get("compliance_failed", 0)),
                 int(bool(summary.get("reboot_required"))), int(summary.get("risk_score", 0)),
                 json.dumps(report), now_iso()),
            )

    def list_scan_results(self, scan_id: str, with_report: bool = True) -> List[Dict[str, Any]]:
        out = []
        for row in self._query("SELECT * FROM scan_results WHERE scan_id = ? ORDER BY hostname", (scan_id,)):
            item = {k: row[k] for k in row.keys() if k != "report"}
            item["reboot_required"] = bool(item["reboot_required"])
            if with_report:
                item["report"] = json.loads(row["report"])
            out.append(item)
        return out

    def latest_scan_id(self, cluster_id: str) -> Optional[str]:
        rows = self._query(
            "SELECT scan_id FROM scan_results WHERE cluster_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (cluster_id,))
        return rows[0]["scan_id"] if rows else None

    # ------------------------------------------------------ patch results
    def save_patch_result(self, patch_id: str, cluster_id: str, hostname: str, status: str,
                          report: Dict[str, Any]) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO patch_results (patch_id, cluster_id, hostname, status, packages_updated,"
                " rebooted, report, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (patch_id, cluster_id, hostname, status, len(report.get("packages_updated") or []),
                 int(bool(report.get("rebooted"))), json.dumps(report), now_iso()),
            )

    def list_patch_results(self, patch_id: str, with_report: bool = True) -> List[Dict[str, Any]]:
        out = []
        for row in self._query("SELECT * FROM patch_results WHERE patch_id = ? ORDER BY hostname", (patch_id,)):
            item = {k: row[k] for k in row.keys() if k != "report"}
            item["rebooted"] = bool(item["rebooted"])
            if with_report:
                item["report"] = json.loads(row["report"])
            out.append(item)
        return out

    # ------------------------------------------------------ installations
    def upsert_installation(self, cluster_id: str, hostname: str, category: str, name: str, version: str,
                            state: str, params: Optional[Dict[str, Any]] = None, job_id: str = "") -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO installations (cluster_id, hostname, category, name, version, state, params, job_id,"
                " updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(cluster_id, hostname, category, name) DO UPDATE SET version=excluded.version,"
                " state=excluded.state, params=excluded.params, job_id=excluded.job_id,"
                " updated_at=excluded.updated_at",
                (cluster_id, hostname, category, name, version, state, json.dumps(params or {}), job_id, now_iso()),
            )

    def set_installation_state(self, cluster_id: str, hostname: str, category: str, name: str, state: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE installations SET state = ?, updated_at = ? WHERE cluster_id = ? AND hostname = ?"
                " AND category = ? AND name = ?",
                (state, now_iso(), cluster_id, hostname, category, name),
            )

    def list_installations(self, cluster_id: str, category: Optional[str] = None,
                           name: Optional[str] = None) -> List[Dict[str, Any]]:
        sql, args = "SELECT * FROM installations WHERE cluster_id = ?", [cluster_id]
        if category:
            sql += " AND category = ?"
            args.append(category)
        if name:
            sql += " AND name = ?"
            args.append(name)
        out = []
        for row in self._query(sql + " ORDER BY name, hostname", tuple(args)):
            item = dict(row)
            item["params"] = json.loads(item["params"])
            out.append(item)
        return out

    def get_installation(self, cluster_id: str, category: str, name: str, hostname: str = "") -> Optional[Dict[str, Any]]:
        for item in self.list_installations(cluster_id, category, name):
            if item["hostname"] == hostname:
                return item
        return None
