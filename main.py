#!/usr/bin/env python3
"""Entry point of the Linux provisioning backend.

    python main.py serve                          # REST API
    python main.py cluster create -f examples/cluster_mixed.json
    python main.py cluster bootstrap analytics
    python main.py version install analytics --technology java --version 17
    python main.py software deploy analytics hadoop -f examples/hadoop_ha.json
    python main.py scan run analytics
    python main.py patch plan analytics
    python main.py patch apply analytics --mode security --strategy rolling

Add ``--dry-run`` before the command to exercise everything without Ansible
touching a machine. Commands that start a job wait for it and exit non-zero if
it did not succeed; pass ``--no-wait`` to return immediately (API server only
makes sense for that, since jobs die with the process).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from provisioner.app import Application
from provisioner.config import load_settings
from provisioner.exceptions import ProvisionerError, ValidationError
from provisioner.models import JOB_SUCCESS, Job


def load_json_file(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        with (sys.stdin if path == "-" else open(path)) as handle:
            data = json.load(handle)
    except OSError as exc:
        raise ValidationError("cannot read %s: %s" % (path, exc))
    except ValueError as exc:
        raise ValidationError("%s is not valid JSON: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ValidationError("%s must contain a JSON object" % path)
    return data


def parse_kv(pairs: Optional[List[str]]) -> Dict[str, Any]:
    """--var key=value; values are parsed as JSON when possible (so numbers,
    booleans and lists work) and kept as strings otherwise."""
    out: Dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise ValidationError("expected key=value, got %r" % pair)
        key, value = pair.split("=", 1)
        try:
            out[key] = json.loads(value)
        except ValueError:
            out[key] = value
    return out


def emit(data: Any) -> None:
    print(json.dumps(data, indent=2, sort_keys=False))


class Cli:
    def __init__(self, app: Application, args: argparse.Namespace):
        self.app = app
        self.args = args

    def finish(self, job: Job) -> int:
        """Wait for a job (unless --no-wait) and map its status to an exit code."""
        if self.args.no_wait:
            emit({"job_id": job.id, "status": job.status,
                  "note": "--no-wait: the job is abandoned when this process exits"})
            return 0
        print("job %s (%s/%s) started; log: %s" % (job.id, job.kind, job.action, job.log_path), file=sys.stderr)
        job = self.app.jobs.wait(job.id)
        emit({"job_id": job.id, "kind": job.kind, "action": job.action, "status": job.status,
              "dry_run": job.dry_run, "error": job.error,
              "steps": [{k: s.get(k) for k in ("name", "status", "failed_hosts", "unreachable_hosts")}
                        for s in job.steps],
              "result": job.result})
        return 0 if job.status == JOB_SUCCESS else 2

    # ---------------------------------------------------------- commands
    def cluster(self) -> int:
        a, c = self.args, self.app.clusters
        if a.action == "create":
            emit(c.create(load_json_file(a.file)))
        elif a.action == "list":
            emit(c.list())
        elif a.action == "show":
            emit(c.get(a.cluster))
        elif a.action == "delete":
            emit(c.delete(a.cluster, force=a.force))
        elif a.action == "add-nodes":
            emit(c.add_nodes(a.cluster, load_json_file(a.file)))
        elif a.action == "remove-node":
            emit(c.remove_node(a.cluster, a.node, force=a.force))
        elif a.action == "ping":
            return self.finish(c.ping(a.cluster, a.nodes))
        elif a.action == "facts":
            return self.finish(c.gather_facts(a.cluster, a.nodes))
        elif a.action == "bootstrap":
            body = load_json_file(a.file)
            body.update(parse_kv(a.var))
            if a.nodes:
                body["nodes"] = a.nodes
            return self.finish(c.bootstrap(a.cluster, body))
        return 0

    def version(self) -> int:
        a, v = self.args, self.app.versions
        if a.action == "catalog":
            emit(v.catalog())
        elif a.action == "list":
            emit(v.list_installed(a.cluster))
        elif a.action == "install":
            return self.finish(v.install(a.cluster, {
                "technology": a.technology, "version": a.version, "nodes": a.nodes, "method": a.method,
                "allow_unlisted": a.allow_unlisted, "options": parse_kv(a.var)}))
        elif a.action == "uninstall":
            return self.finish(v.uninstall(a.cluster, {
                "technology": a.technology, "version": a.version, "nodes": a.nodes, "force": a.force}))
        return 0

    def software(self) -> int:
        a, s = self.args, self.app.software
        if a.action == "catalog":
            emit(s.catalog())
            return 0
        if a.action == "list":
            emit(s.list_deployed(a.cluster))
            return 0
        body = load_json_file(getattr(a, "file", None))
        extra_vars = parse_kv(getattr(a, "var", None))
        if extra_vars:
            body.setdefault("vars", {}).update(extra_vars)
        for key in ("version", "mode", "nodes"):
            if getattr(a, key, None):
                body[key] = getattr(a, key)
        if a.action == "plan":
            emit(s.plan(a.cluster, a.name, body))
            return 0
        if a.action == "deploy":
            return self.finish(s.deploy(a.cluster, a.name, body))
        # generic action: start/stop/restart/status/scale_out/decommission/promote/uninstall...
        if getattr(a, "node", None):
            body["node"] = a.node
        if getattr(a, "purge_data", False):
            body.update({"purge_data": True, "confirm_purge": a.confirm_purge})
        return self.finish(s.action(a.cluster, a.name, a.operation, body))

    def scan(self) -> int:
        a, s = self.args, self.app.scans
        if a.action == "run":
            return self.finish(s.run(a.cluster, {"scan_type": a.type, "nodes": a.nodes,
                                                 "refresh_cache": not a.no_refresh}))
        if a.action == "list":
            emit(s.list(a.cluster))
        elif a.action == "latest":
            emit(s.latest(a.cluster, with_reports=a.reports))
        elif a.action == "show":
            emit(s.get(a.scan_id, with_reports=a.reports, hostname=a.host))
        elif a.action == "compliance":
            emit(s.compliance(a.scan_id))
        elif a.action == "diff":
            emit(s.diff(a.scan_id, a.other_scan_id))
        return 0

    def patch(self) -> int:
        a, p = self.args, self.app.patches
        if a.action in ("plan", "apply"):
            body = load_json_file(a.file)
            for key in ("mode", "strategy", "reboot", "batch_size", "nodes", "packages", "exclude",
                        "canary_nodes", "services_to_verify"):
                if getattr(a, key, None):
                    body[key] = getattr(a, key)
            if a.action == "plan":
                emit(p.plan(a.cluster, body))
                return 0
            for flag in ("check", "force"):
                if getattr(a, flag):
                    body[flag] = True
            if a.no_kernel:
                body["kernel_update"] = False
            if a.no_post_scan:
                body["post_scan"] = False
            return self.finish(p.apply(a.cluster, body))
        if a.action == "list":
            emit(p.list(a.cluster))
        elif a.action == "show":
            emit(p.get(a.patch_id, with_reports=a.reports))
        elif a.action == "rollback":
            return self.finish(p.rollback(a.patch_id, {"nodes": a.nodes}))
        return 0

    def job(self) -> int:
        a = self.args
        if a.action == "list":
            cluster_id = self.app.store.get_cluster(a.cluster).id if a.cluster else None
            emit([{k: j.to_dict()[k] for k in ("id", "kind", "action", "status", "dry_run", "created_at",
                                                "finished_at", "error")}
                  for j in self.app.store.list_jobs(cluster_id=cluster_id, kind=a.kind, limit=a.limit)])
        elif a.action == "show":
            emit(self.app.store.get_job(a.job_id).to_dict())
        elif a.action == "log":
            sys.stdout.write(self.app.jobs.read_log(a.job_id, a.tail))
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description="Linux provisioning backend",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    parser.add_argument("--config", help="JSON config file (or env PROVISIONER_CONFIG)")
    parser.add_argument("--data-dir", help="where the database, logs and reports live")
    parser.add_argument("--dry-run", action="store_true", help="simulate every Ansible run; no host is contacted")
    parser.add_argument("--no-wait", action="store_true", help="do not wait for jobs to finish")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="ansible verbosity (-v .. -vvvv)")
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    serve = sub.add_parser("serve", help="run the REST API")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)

    def nodes_arg(p):
        p.add_argument("--nodes", nargs="+", metavar="HOST", help="restrict to these nodes (default: all)")

    # cluster
    cluster = sub.add_parser("cluster", help="clusters and nodes").add_subparsers(dest="action")
    cluster.required = True
    p = cluster.add_parser("create"); p.add_argument("-f", "--file", required=True, help="cluster spec JSON")
    cluster.add_parser("list")
    p = cluster.add_parser("show"); p.add_argument("cluster")
    p = cluster.add_parser("delete"); p.add_argument("cluster"); p.add_argument("--force", action="store_true")
    p = cluster.add_parser("add-nodes"); p.add_argument("cluster"); p.add_argument("-f", "--file", required=True)
    p = cluster.add_parser("remove-node"); p.add_argument("cluster"); p.add_argument("node")
    p.add_argument("--force", action="store_true")
    for name in ("ping", "facts"):
        p = cluster.add_parser(name); p.add_argument("cluster"); nodes_arg(p)
    p = cluster.add_parser("bootstrap"); p.add_argument("cluster"); nodes_arg(p)
    p.add_argument("-f", "--file", help="bootstrap options JSON")
    p.add_argument("--var", action="append", metavar="KEY=VALUE")

    # version
    version = sub.add_parser("version", help="technology versions (java, python, nodejs, golang, docker)")
    version = version.add_subparsers(dest="action")
    version.required = True
    version.add_parser("catalog")
    p = version.add_parser("list"); p.add_argument("cluster")
    for name in ("install", "uninstall"):
        p = version.add_parser(name); p.add_argument("cluster")
        p.add_argument("--technology", required=True); p.add_argument("--version"); nodes_arg(p)
        if name == "install":
            p.add_argument("--method"); p.add_argument("--allow-unlisted", action="store_true")
            p.add_argument("--var", action="append", metavar="KEY=VALUE")
        else:
            p.add_argument("--force", action="store_true")

    # software
    software = sub.add_parser("software", help="clustered software (hadoop, redis, postgresql)")
    software = software.add_subparsers(dest="action")
    software.required = True
    software.add_parser("catalog")
    p = software.add_parser("list"); p.add_argument("cluster")
    for name in ("plan", "deploy"):
        p = software.add_parser(name); p.add_argument("cluster"); p.add_argument("name")
        p.add_argument("-f", "--file", help="deployment spec JSON (version, mode, roles, vars)")
        p.add_argument("--version"); p.add_argument("--mode"); nodes_arg(p)
        p.add_argument("--var", action="append", metavar="KEY=VALUE")
    p = software.add_parser("action", help="start|stop|restart|status|scale_out|decommission|promote|uninstall")
    p.add_argument("cluster"); p.add_argument("name"); p.add_argument("operation")
    p.add_argument("-f", "--file", help="action body JSON (e.g. roles for scale_out)")
    nodes_arg(p); p.add_argument("--node", help="single node (promote)")
    p.add_argument("--purge-data", action="store_true"); p.add_argument("--confirm-purge", action="store_true")

    # scan
    scan = sub.add_parser("scan", help="scan VMs for updates and compliance").add_subparsers(dest="action")
    scan.required = True
    p = scan.add_parser("run"); p.add_argument("cluster"); nodes_arg(p)
    p.add_argument("--type", default="full", choices=["full", "vulnerability", "compliance", "inventory"])
    p.add_argument("--no-refresh", action="store_true", help="do not refresh the package cache first")
    p = scan.add_parser("list"); p.add_argument("cluster")
    p = scan.add_parser("latest"); p.add_argument("cluster"); p.add_argument("--reports", action="store_true")
    p = scan.add_parser("show"); p.add_argument("scan_id"); p.add_argument("--reports", action="store_true")
    p.add_argument("--host")
    p = scan.add_parser("compliance"); p.add_argument("scan_id")
    p = scan.add_parser("diff"); p.add_argument("scan_id"); p.add_argument("other_scan_id")

    # patch
    patch = sub.add_parser("patch", help="patch VMs").add_subparsers(dest="action")
    patch.required = True
    for name in ("plan", "apply"):
        p = patch.add_parser(name); p.add_argument("cluster"); nodes_arg(p)
        p.add_argument("-f", "--file", help="patch options JSON")
        p.add_argument("--mode", choices=["security", "all", "packages"])
        p.add_argument("--strategy", choices=["rolling", "canary", "all_at_once"])
        p.add_argument("--reboot", choices=["never", "if_required", "always"])
        p.add_argument("--batch-size", dest="batch_size")
        p.add_argument("--packages", nargs="+"); p.add_argument("--exclude", nargs="+")
        p.add_argument("--canary-nodes", dest="canary_nodes", nargs="+")
        p.add_argument("--verify-services", dest="services_to_verify", nargs="+")
        if name == "apply":
            p.add_argument("--check", action="store_true", help="run the patch scripts in report-only mode")
            p.add_argument("--force", action="store_true")
            p.add_argument("--no-kernel", action="store_true")
            p.add_argument("--no-post-scan", action="store_true")
    p = patch.add_parser("list"); p.add_argument("cluster")
    p = patch.add_parser("show"); p.add_argument("patch_id"); p.add_argument("--reports", action="store_true")
    p = patch.add_parser("rollback"); p.add_argument("patch_id"); nodes_arg(p)

    # job
    job = sub.add_parser("job", help="inspect jobs").add_subparsers(dest="action")
    job.required = True
    p = job.add_parser("list"); p.add_argument("--cluster"); p.add_argument("--kind")
    p.add_argument("--limit", type=int, default=20)
    p = job.add_parser("show"); p.add_argument("job_id")
    p = job.add_parser("log"); p.add_argument("job_id"); p.add_argument("--tail", type=int)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    app = None
    try:
        settings = load_settings(args.config, data_dir=args.data_dir, dry_run=True if args.dry_run else None,
                                 ansible_verbosity=args.verbose or None)
        app = Application(settings)
        if args.command == "serve":
            from provisioner.api.server import serve
            serve(app, args.host, args.port)
            app = None  # serve() closes it
            return 0
        return getattr(Cli(app, args), args.command)()
    except ProvisionerError as exc:
        print(json.dumps(exc.to_dict(), indent=2), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    finally:
        if app is not None:
            app.close(wait=False)


if __name__ == "__main__":
    sys.exit(main())
