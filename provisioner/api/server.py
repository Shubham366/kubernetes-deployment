"""REST API on the standard library's threaded HTTP server.

Every mutating operation returns ``202`` with a job; poll ``/api/v1/jobs/<id>``
for the outcome. Routes are declared in ``build_routes``.
"""
from __future__ import annotations

import hmac
import json
import logging
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..app import Application
from ..exceptions import AuthError, NotFoundError, ProvisionerError, ValidationError
from ..models import Job

log = logging.getLogger("provisioner.api")

MAX_BODY_BYTES = 2 * 1024 * 1024
# handler(app, path_params, query, body) -> (status, payload)
Handler = Callable[[Application, Dict[str, str], Dict[str, str], Dict[str, Any]], Tuple[int, Any]]


def _flag(query: Dict[str, str], name: str) -> bool:
    return query.get(name, "").lower() in ("1", "true", "yes")


def _job(job: Job) -> Tuple[int, Any]:
    return 202, {"job": job.to_dict(), "links": {"job": "/api/v1/jobs/%s" % job.id,
                                                 "log": "/api/v1/jobs/%s/log" % job.id}}


def build_routes() -> List[Tuple[str, "re.Pattern[str]", Handler]]:
    routes: List[Tuple[str, str, Handler]] = []

    def route(method: str, pattern: str):
        def register(fn: Handler) -> Handler:
            routes.append((method, pattern, fn))
            return fn
        return register

    # ------------------------------------------------------------ general
    @route("GET", "/health")
    def health(app, p, q, b):
        return 200, {"status": "ok", "version": __version__, "dry_run": app.settings.dry_run,
                     "ansible_available": app.settings.ansible_available()}

    @route("GET", "/api/v1/catalog")
    def catalog(app, p, q, b):
        return 200, {"technologies": app.versions.catalog(), "software": app.software.catalog()}

    # ----------------------------------------------------------- clusters
    @route("GET", "/api/v1/clusters")
    def clusters_list(app, p, q, b):
        return 200, {"clusters": app.clusters.list()}

    @route("POST", "/api/v1/clusters")
    def clusters_create(app, p, q, b):
        return 201, app.clusters.create(b)

    @route("GET", "/api/v1/clusters/{cluster}")
    def clusters_get(app, p, q, b):
        return 200, app.clusters.get(p["cluster"])

    @route("DELETE", "/api/v1/clusters/{cluster}")
    def clusters_delete(app, p, q, b):
        return 200, app.clusters.delete(p["cluster"], force=_flag(q, "force"))

    @route("POST", "/api/v1/clusters/{cluster}/nodes")
    def nodes_add(app, p, q, b):
        return 201, app.clusters.add_nodes(p["cluster"], b)

    @route("PATCH", "/api/v1/clusters/{cluster}/nodes/{node}")
    def nodes_update(app, p, q, b):
        return 200, app.clusters.update_node(p["cluster"], p["node"], b)

    @route("DELETE", "/api/v1/clusters/{cluster}/nodes/{node}")
    def nodes_delete(app, p, q, b):
        return 200, app.clusters.remove_node(p["cluster"], p["node"], force=_flag(q, "force"))

    @route("POST", "/api/v1/clusters/{cluster}/ping")
    def clusters_ping(app, p, q, b):
        return _job(app.clusters.ping(p["cluster"], b.get("nodes"), dry_run=bool(b.get("dry_run"))))

    @route("POST", "/api/v1/clusters/{cluster}/facts")
    def clusters_facts(app, p, q, b):
        return _job(app.clusters.gather_facts(p["cluster"], b.get("nodes"), dry_run=bool(b.get("dry_run"))))

    @route("POST", "/api/v1/clusters/{cluster}/bootstrap")
    def clusters_bootstrap(app, p, q, b):
        return _job(app.clusters.bootstrap(p["cluster"], b, dry_run=bool(b.get("dry_run"))))

    # ----------------------------------------------- technology versions
    @route("GET", "/api/v1/clusters/{cluster}/versions")
    def versions_list(app, p, q, b):
        return 200, {"installed": app.versions.list_installed(p["cluster"])}

    @route("POST", "/api/v1/clusters/{cluster}/versions")
    def versions_install(app, p, q, b):
        return _job(app.versions.install(p["cluster"], b))

    @route("DELETE", "/api/v1/clusters/{cluster}/versions/{technology}")
    def versions_uninstall(app, p, q, b):
        body = dict(b, technology=p["technology"])
        body.setdefault("force", _flag(q, "force"))
        return _job(app.versions.uninstall(p["cluster"], body))

    # ----------------------------------------------------------- software
    @route("GET", "/api/v1/clusters/{cluster}/software")
    def software_list(app, p, q, b):
        return 200, {"deployed": app.software.list_deployed(p["cluster"])}

    @route("POST", "/api/v1/clusters/{cluster}/software/{name}/plan")
    def software_plan(app, p, q, b):
        return 200, app.software.plan(p["cluster"], p["name"], b)

    @route("POST", "/api/v1/clusters/{cluster}/software/{name}")
    def software_deploy(app, p, q, b):
        return _job(app.software.deploy(p["cluster"], p["name"], b))

    @route("POST", "/api/v1/clusters/{cluster}/software/{name}/actions/{action}")
    def software_action(app, p, q, b):
        return _job(app.software.action(p["cluster"], p["name"], p["action"], b))

    # ----------------------------------------------------------- scanning
    @route("GET", "/api/v1/clusters/{cluster}/scans")
    def scans_list(app, p, q, b):
        return 200, {"scans": app.scans.list(p["cluster"])}

    @route("POST", "/api/v1/clusters/{cluster}/scans")
    def scans_run(app, p, q, b):
        return _job(app.scans.run(p["cluster"], b))

    @route("GET", "/api/v1/clusters/{cluster}/scans/latest")
    def scans_latest(app, p, q, b):
        return 200, app.scans.latest(p["cluster"], with_reports=_flag(q, "reports"))

    @route("GET", "/api/v1/scans/{scan}")
    def scans_get(app, p, q, b):
        return 200, app.scans.get(p["scan"], with_reports=_flag(q, "reports"), hostname=q.get("host"))

    @route("GET", "/api/v1/scans/{scan}/compliance")
    def scans_compliance(app, p, q, b):
        return 200, app.scans.compliance(p["scan"])

    @route("GET", "/api/v1/scans/{scan}/diff/{other}")
    def scans_diff(app, p, q, b):
        return 200, app.scans.diff(p["scan"], p["other"])

    # ----------------------------------------------------------- patching
    @route("GET", "/api/v1/clusters/{cluster}/patches")
    def patches_list(app, p, q, b):
        return 200, {"patches": app.patches.list(p["cluster"])}

    @route("POST", "/api/v1/clusters/{cluster}/patches/plan")
    def patches_plan(app, p, q, b):
        return 200, app.patches.plan(p["cluster"], b)

    @route("POST", "/api/v1/clusters/{cluster}/patches")
    def patches_apply(app, p, q, b):
        return _job(app.patches.apply(p["cluster"], b))

    @route("GET", "/api/v1/patches/{patch}")
    def patches_get(app, p, q, b):
        return 200, app.patches.get(p["patch"], with_reports=_flag(q, "reports"))

    @route("POST", "/api/v1/patches/{patch}/rollback")
    def patches_rollback(app, p, q, b):
        return _job(app.patches.rollback(p["patch"], b))

    # --------------------------------------------------------------- jobs
    @route("GET", "/api/v1/jobs")
    def jobs_list(app, p, q, b):
        cluster_id = app.store.get_cluster(q["cluster"]).id if q.get("cluster") else None
        try:
            limit = int(q.get("limit", "50"))
        except ValueError:
            raise ValidationError("limit must be an integer")
        jobs = app.store.list_jobs(cluster_id=cluster_id, kind=q.get("kind"), status=q.get("status"), limit=limit)
        return 200, {"jobs": [j.to_dict() for j in jobs]}

    @route("GET", "/api/v1/jobs/{job}")
    def jobs_get(app, p, q, b):
        return 200, app.store.get_job(p["job"]).to_dict()

    @route("GET", "/api/v1/jobs/{job}/log")
    def jobs_log(app, p, q, b):
        tail = None
        if q.get("tail"):
            try:
                tail = max(1, int(q["tail"]))
            except ValueError:
                raise ValidationError("tail must be an integer")
        return 200, {"job_id": p["job"], "log": app.jobs.read_log(p["job"], tail)}

    @route("POST", "/api/v1/jobs/{job}/cancel")
    def jobs_cancel(app, p, q, b):
        return 202, {"job": app.jobs.cancel(p["job"]).to_dict(), "note": "cancellation requested"}

    compiled = []
    for method, pattern, fn in routes:
        regex = "^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", pattern) + "/?$"
        compiled.append((method, re.compile(regex), fn))
    return compiled


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, app: Application, host: str, port: int):
        self.app = app
        self.routes = build_routes()
        super().__init__((host, port), RequestHandler)

    def dispatch(self, method: str, raw_path: str, headers, body_bytes: bytes) -> Tuple[int, Any]:
        """Transport-independent request handling (also used by the tests)."""
        try:
            parsed = urlparse(raw_path)
            query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}
            token = self.app.settings.api_token
            if token and parsed.path != "/health":
                supplied = (headers.get("Authorization") or "")
                expected = "Bearer %s" % token
                if not hmac.compare_digest(supplied.encode(), expected.encode()):
                    raise AuthError("missing or invalid bearer token")

            path_matched = False
            for route_method, regex, handler in self.routes:
                match = regex.match(parsed.path)
                if not match:
                    continue
                path_matched = True
                if route_method != method:
                    continue
                body: Dict[str, Any] = {}
                if body_bytes.strip():
                    try:
                        body = json.loads(body_bytes.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        raise ValidationError("request body is not valid JSON")
                    if not isinstance(body, dict):
                        raise ValidationError("request body must be a JSON object")
                return handler(self.app, match.groupdict(), query, body)
            if path_matched:
                return 405, {"error": "MethodNotAllowed", "message": "%s not allowed on %s" % (method, parsed.path)}
            raise NotFoundError("no such endpoint: %s" % parsed.path)
        except ProvisionerError as exc:
            return exc.status, exc.to_dict()
        except Exception as exc:  # last line of defence: never leak a traceback to the client
            log.exception("unhandled error for %s %s", method, raw_path)
            return 500, {"error": "InternalError", "message": str(exc)}


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "LinuxProvisioner/" + __version__
    protocol_version = "HTTP/1.1"

    def _handle(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self._send(413, {"error": "PayloadTooLarge", "message": "body must be at most %d bytes" % MAX_BODY_BYTES})
            return
        body = self.rfile.read(length) if length else b""
        status, payload = self.server.dispatch(self.command, self.path, self.headers, body)  # type: ignore
        self._send(status, payload)

    def _send(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = do_PATCH = do_PUT = _handle

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s %s", self.address_string(), fmt % args)


def serve(app: Application, host: Optional[str] = None, port: Optional[int] = None) -> None:
    host = host or app.settings.api_host
    port = port or app.settings.api_port
    server = ApiServer(app, host, port)
    if host not in ("127.0.0.1", "localhost", "::1") and not app.settings.api_token:
        log.warning("API is listening on %s without api_token: anyone who can reach it can run "
                    "playbooks on your machines", host)
    log.info("provisioner API listening on http://%s:%d (dry_run=%s)", host, port, app.settings.dry_run)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        server.server_close()
        app.close(wait=False)
