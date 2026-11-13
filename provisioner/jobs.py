"""Asynchronous job engine.

A job is an ordered pipeline of playbook steps run against one cluster. Jobs
for the same cluster are serialised (two playbooks changing the same machines
at once is how clusters get broken); different clusters run in parallel up to
``max_workers``.
"""
from __future__ import annotations

import logging
import threading
import traceback
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .config import Settings
from .exceptions import ConflictError, NotFoundError, ProvisionerError
from .executor import AnsibleExecutor, PlaybookResult
from .inventory import InventoryBuilder
from .models import (JOB_CANCELLED, JOB_FAILED, JOB_PARTIAL, JOB_PENDING, JOB_RUNNING, JOB_SUCCESS, Cluster,
                     Job, mask_secrets, now_iso)
from .store import Store

log = logging.getLogger("provisioner.jobs")


@dataclass
class Step:
    name: str
    playbook: str                      # relative to ansible/playbooks
    extra_vars: Dict[str, Any] = field(default_factory=dict)
    limit: Optional[List[str]] = None  # hostnames; None = every host in the inventory
    tags: Optional[List[str]] = None
    check: bool = False
    # Keep going with later steps even if this one fails (e.g. a verification scan).
    continue_on_failure: bool = False
    # Evaluated just before the step with the results so far; False -> skipped.
    condition: Optional[Callable[[List[PlaybookResult]], bool]] = None
    on_simulate: Optional[Callable[[List[str], Dict[str, Any]], None]] = None


# finalize(job, results) -> result dict. May include "_status" to override the
# computed job status (e.g. a scan where some hosts produced no report).
Finalizer = Callable[[Job, List[PlaybookResult]], Dict[str, Any]]


class JobManager:
    def __init__(self, settings: Settings, store: Store, inventory: InventoryBuilder, executor: AnsibleExecutor):
        self.settings = settings
        self.store = store
        self.inventory = inventory
        self.executor = executor
        self._pool = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="job")
        self._futures: Dict[str, Future] = {}
        self._cancel: Dict[str, threading.Event] = {}
        self._cluster_locks: Dict[str, threading.Lock] = {}
        self._guard = threading.Lock()
        stale = store.mark_stale_jobs_interrupted()
        if stale:
            log.warning("marked %d stale job(s) as interrupted", stale)

    # ------------------------------------------------------------------
    def _cluster_lock(self, cluster_id: str) -> threading.Lock:
        with self._guard:
            return self._cluster_locks.setdefault(cluster_id, threading.Lock())

    def active_jobs(self, cluster_id: str) -> List[Job]:
        return [j for j in self.store.list_jobs(cluster_id=cluster_id, limit=200)
                if j.status in (JOB_PENDING, JOB_RUNNING)]

    def submit(self, cluster: Cluster, kind: str, action: str, steps: List[Step],
               params: Optional[Dict[str, Any]] = None, finalize: Optional[Finalizer] = None,
               inventory_hosts: Optional[List[str]] = None, dry_run: bool = False,
               reject_if_busy: bool = False, extra_groups: Optional[Dict[str, List[str]]] = None,
               job_id: Optional[str] = None) -> Job:
        """Queue a job and return immediately. ``inventory_hosts`` restricts the
        generated inventory (default: all active nodes of the cluster)."""
        if not steps:
            raise ProvisionerError("job has no steps")
        if reject_if_busy and self.active_jobs(cluster.id):
            raise ConflictError("cluster %s already has a job in progress" % cluster.name)
        # validate playbooks up front so a typo fails the request, not the job
        for step in steps:
            self.settings.playbook_path(step.playbook)

        simulate = bool(dry_run or self.settings.dry_run)
        if not simulate:
            simulate = self.executor.should_simulate()  # raises if ansible is missing
        job = Job(cluster_id=cluster.id, kind=kind, action=action, params=mask_secrets(params or {}),
                  dry_run=simulate)
        if job_id:
            # callers that need the id up front (report directories) choose it
            job.id = job_id
        job.log_path = str(self.settings.log_dir / ("%s.log" % job.id))
        job.steps = [{"name": s.name, "playbook": s.playbook, "status": "pending", "limit": s.limit}
                     for s in steps]
        self.store.save_job(job)

        cancel = threading.Event()
        with self._guard:
            self._cancel[job.id] = cancel
            self._futures[job.id] = self._pool.submit(
                self._run, job, steps, finalize, inventory_hosts, simulate, cancel, extra_groups)
        return job

    def wait(self, job_id: str, timeout: Optional[float] = None) -> Job:
        future = self._futures.get(job_id)
        if future is not None:
            future.result(timeout=timeout)
        return self.store.get_job(job_id)

    def cancel(self, job_id: str) -> Job:
        job = self.store.get_job(job_id)
        if job.finished:
            raise ConflictError("job %s already finished with status %s" % (job_id, job.status))
        event = self._cancel.get(job_id)
        if event is None:
            raise NotFoundError("job %s is not owned by this process" % job_id)
        event.set()
        return job

    def read_log(self, job_id: str, tail: Optional[int] = None) -> str:
        job = self.store.get_job(job_id)
        try:
            with open(job.log_path, "r", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            return ""
        if tail:
            lines = lines[-int(tail):]
        return "".join(lines)

    def shutdown(self, wait: bool = True) -> None:
        self._pool.shutdown(wait=wait)

    # ------------------------------------------------------------------
    def _run(self, job: Job, steps: List[Step], finalize: Optional[Finalizer],
             inventory_hosts: Optional[List[str]], simulate: bool, cancel: threading.Event,
             extra_groups: Optional[Dict[str, List[str]]] = None) -> None:
        results: List[PlaybookResult] = []
        with self._cluster_lock(job.cluster_id):
            try:
                if cancel.is_set():
                    job.status = JOB_CANCELLED
                    return
                job.status = JOB_RUNNING
                job.started_at = now_iso()
                self.store.save_job(job)

                # Re-read the cluster: an earlier queued job may have changed it.
                cluster = self.store.get_cluster(job.cluster_id)
                nodes = cluster.resolve_nodes(inventory_hosts) if inventory_hosts else None
                inventory_path = self.inventory.write(cluster, job.id, nodes, extra_groups)

                aborted = False
                for index, step in enumerate(steps):
                    record = job.steps[index]
                    if aborted or cancel.is_set():
                        record["status"] = "skipped"
                        continue
                    if step.condition is not None and not step.condition(results):
                        record["status"] = "skipped"
                        record["reason"] = "condition not met"
                        continue
                    record["status"] = "running"
                    record["started_at"] = now_iso()
                    self.store.save_job(job)

                    result = self.executor.run(
                        step.playbook, inventory_path, run_id="%s-%d" % (job.id, index),
                        extra_vars=step.extra_vars, limit=step.limit, tags=step.tags, check=step.check,
                        log_path=job.log_path, cancel_event=cancel, simulate=simulate,
                        on_simulate=step.on_simulate,
                    )
                    results.append(result)
                    record.update(result.to_dict())
                    record["status"] = "success" if result.ok else ("cancelled" if result.cancelled else "failed")
                    record["finished_at"] = now_iso()
                    self.store.save_job(job)
                    if not result.ok and not step.continue_on_failure:
                        aborted = True

                job.status = self._status_from(results, steps, cancel)
                if finalize is not None:
                    outcome = finalize(job, results) or {}
                    override = outcome.pop("_status", None)
                    if override and job.status != JOB_CANCELLED:
                        job.status = override
                    job.result = outcome
                if job.status in (JOB_FAILED, JOB_PARTIAL) and not job.error:
                    job.error = self._describe_failure(results)
            except ProvisionerError as exc:
                job.status = JOB_FAILED
                job.error = exc.message
            except Exception as exc:  # never let a worker die silently
                log.exception("job %s crashed", job.id)
                job.status = JOB_FAILED
                job.error = "internal error: %s" % exc
                self._append_log(job, traceback.format_exc())
            finally:
                job.finished_at = now_iso()
                self.store.save_job(job)
                with self._guard:
                    self._cancel.pop(job.id, None)
                log.info("job %s (%s/%s) finished: %s", job.id, job.kind, job.action, job.status)

    @staticmethod
    def _status_from(results: List[PlaybookResult], steps: List[Step], cancel: threading.Event) -> str:
        if cancel.is_set() or any(r.cancelled for r in results):
            return JOB_CANCELLED
        if not results:
            return JOB_FAILED
        if all(r.ok for r in results):
            return JOB_SUCCESS
        # Something failed. If hosts still completed in the failing step(s),
        # the cluster is in a mixed state and that must be visible.
        failing = [r for r in results if not r.ok]
        if any(r.ok_hosts for r in failing) and not any(r.timed_out for r in failing):
            return JOB_PARTIAL
        return JOB_FAILED

    @staticmethod
    def _describe_failure(results: List[PlaybookResult]) -> str:
        parts = []
        for r in results:
            if r.ok:
                continue
            bits = ["%s: rc=%s" % (r.playbook, r.rc)]
            if r.timed_out:
                bits.append("timed out")
            if r.failed_hosts:
                bits.append("failed on %s" % ", ".join(r.failed_hosts))
            if r.unreachable_hosts:
                bits.append("unreachable: %s" % ", ".join(r.unreachable_hosts))
            parts.append(" ".join(bits))
        return "; ".join(parts) or "job failed (see log)"

    @staticmethod
    def _append_log(job: Job, text: str) -> None:
        try:
            with open(job.log_path, "a") as handle:
                handle.write("\n" + text)
        except OSError:
            pass
