"""Shared plumbing for controllers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ..config import Settings
from ..exceptions import ValidationError
from ..executor import AnsibleExecutor
from ..inventory import InventoryBuilder
from ..jobs import Finalizer, JobManager, Step
from ..models import Cluster, Job
from ..store import Store


@dataclass
class AppContext:
    settings: Settings
    store: Store
    inventory: InventoryBuilder
    executor: AnsibleExecutor
    jobs: JobManager


class BaseController:
    kind = "generic"

    def __init__(self, ctx: AppContext):
        self.ctx = ctx
        self.settings = ctx.settings
        self.store = ctx.store
        self.jobs = ctx.jobs

    def cluster(self, ref: str) -> Cluster:
        return self.store.get_cluster(ref)

    def submit(self, cluster: Cluster, action: str, steps: List[Step], params: Optional[Dict[str, Any]] = None,
               finalize: Optional[Finalizer] = None, inventory_hosts: Optional[List[str]] = None,
               dry_run: bool = False, extra_groups: Optional[Dict[str, List[str]]] = None,
               job_id: Optional[str] = None) -> Job:
        return self.jobs.submit(cluster, self.kind, action, steps, params=params, finalize=finalize,
                                inventory_hosts=inventory_hosts, dry_run=dry_run, extra_groups=extra_groups,
                                job_id=job_id)

    def is_simulated(self, dry_run: bool = False) -> bool:
        """True when the job about to be submitted will not really run Ansible
        (so controllers must not persist state changes for it)."""
        return bool(dry_run or self.settings.dry_run) or self.ctx.executor.should_simulate()

    # ---- small input helpers ------------------------------------------
    @staticmethod
    def require(body: Dict[str, Any], key: str) -> Any:
        if not isinstance(body, dict) or body.get(key) in (None, "", []):
            raise ValidationError("missing required field: %s" % key)
        return body[key]

    @staticmethod
    def as_bool(value: Any, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")

    @staticmethod
    def as_int(value: Any, name: str, default: int, minimum: Optional[int] = None,
               maximum: Optional[int] = None) -> int:
        if value is None:
            return default
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValidationError("%s must be an integer" % name)
        if minimum is not None and number < minimum:
            raise ValidationError("%s must be >= %d" % (name, minimum))
        if maximum is not None and number > maximum:
            raise ValidationError("%s must be <= %d" % (name, maximum))
        return number

    @staticmethod
    def as_list(value: Any, name: str) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [v.strip() for v in value.split(",") if v.strip()]
        if isinstance(value, list):
            return [str(v) for v in value]
        raise ValidationError("%s must be a list" % name)
