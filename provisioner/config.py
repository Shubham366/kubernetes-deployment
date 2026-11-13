"""Runtime settings.

Precedence (lowest to highest): built-in defaults, JSON config file,
``PROVISIONER_*`` environment variables, explicit overrides (CLI flags).
"""
from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, Optional

from .exceptions import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    project_root: Path = PROJECT_ROOT
    ansible_dir: Path = PROJECT_ROOT / "ansible"
    data_dir: Path = PROJECT_ROOT / "data"

    ansible_playbook_bin: str = "ansible-playbook"
    # dry_run=True never invokes Ansible: every step is simulated and logged.
    dry_run: bool = False
    # When the ansible binary is missing: simulate instead of failing the job.
    simulate_when_ansible_missing: bool = False
    ansible_verbosity: int = 0
    ansible_forks: int = 20

    max_workers: int = 4
    job_timeout_seconds: int = 4 * 3600

    default_ssh_user: str = "root"
    default_ssh_port: int = 22
    default_ssh_key_path: str = ""

    api_host: str = "127.0.0.1"
    api_port: int = 8080
    # When set, every API request must send "Authorization: Bearer <token>".
    api_token: str = ""

    log_level: str = "INFO"
    extra: Dict[str, Any] = field(default_factory=dict)

    # ---- derived paths -------------------------------------------------
    @property
    def db_path(self) -> Path:
        return self.data_dir / "provisioner.db"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def inventory_dir(self) -> Path:
        return self.data_dir / "inventories"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def vars_dir(self) -> Path:
        return self.data_dir / "vars"

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.log_dir, self.inventory_dir, self.reports_dir, self.vars_dir):
            path.mkdir(parents=True, exist_ok=True)
        # extra-vars files can hold passwords
        os.chmod(self.vars_dir, 0o700)

    def ansible_available(self) -> bool:
        return shutil.which(self.ansible_playbook_bin) is not None

    def playbook_path(self, relative: str) -> Path:
        path = (self.ansible_dir / "playbooks" / relative).resolve()
        if not path.is_file():
            raise ValidationError("playbook not found: %s" % path)
        return path

    def to_dict(self) -> Dict[str, Any]:
        out = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "api_token":
                value = "***" if value else ""
            out[f.name] = str(value) if isinstance(value, Path) else value
        return out


_PATH_FIELDS = {"project_root", "ansible_dir", "data_dir"}
_BOOL_TRUE = {"1", "true", "yes", "on"}


def _coerce(name: str, current: Any, raw: Any) -> Any:
    if name in _PATH_FIELDS:
        return Path(str(raw)).expanduser().resolve()
    if isinstance(current, bool):
        return raw if isinstance(raw, bool) else str(raw).strip().lower() in _BOOL_TRUE
    if isinstance(current, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            raise ValidationError("setting %s must be an integer, got %r" % (name, raw))
    return raw


def load_settings(config_file: Optional[str] = None, **overrides: Any) -> Settings:
    settings = Settings()
    known = {f.name for f in fields(Settings)} - {"extra"}

    config_file = config_file or os.environ.get("PROVISIONER_CONFIG")
    if config_file:
        path = Path(config_file).expanduser()
        if not path.is_file():
            raise ValidationError("config file not found: %s" % path)
        try:
            data = json.loads(path.read_text())
        except ValueError as exc:
            raise ValidationError("config file is not valid JSON: %s" % exc)
        for key, value in data.items():
            if key in known:
                setattr(settings, key, _coerce(key, getattr(settings, key), value))
            else:
                settings.extra[key] = value

    for name in known:
        env = os.environ.get("PROVISIONER_" + name.upper())
        if env is not None:
            setattr(settings, name, _coerce(name, getattr(settings, name), env))

    for key, value in overrides.items():
        if value is None:
            continue
        if key not in known:
            raise ValidationError("unknown setting: %s" % key)
        setattr(settings, key, _coerce(key, getattr(settings, key), value))

    settings.ensure_dirs()
    return settings
