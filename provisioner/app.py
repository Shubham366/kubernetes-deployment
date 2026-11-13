"""Application wiring: builds the shared services and the controllers."""
from __future__ import annotations

import logging
from typing import Optional

from .config import Settings, load_settings
from .controllers import (ClusterController, PatchController, ScanController, SoftwareController,
                          VersionController)
from .controllers.base import AppContext
from .executor import AnsibleExecutor
from .inventory import InventoryBuilder
from .jobs import JobManager
from .store import Store


class Application:
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or load_settings()
        logging.basicConfig(
            level=getattr(logging, str(self.settings.log_level).upper(), logging.INFO),
            format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        )
        self.store = Store(self.settings.db_path)
        self.inventory = InventoryBuilder(self.settings)
        self.executor = AnsibleExecutor(self.settings)
        self.jobs = JobManager(self.settings, self.store, self.inventory, self.executor)
        self.ctx = AppContext(self.settings, self.store, self.inventory, self.executor, self.jobs)

        self.clusters = ClusterController(self.ctx)
        self.versions = VersionController(self.ctx)
        self.software = SoftwareController(self.ctx, self.clusters)
        self.scans = ScanController(self.ctx)
        self.patches = PatchController(self.ctx, self.scans)

    def close(self, wait: bool = True) -> None:
        self.jobs.shutdown(wait=wait)
        self.store.close()
