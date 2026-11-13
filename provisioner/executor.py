"""Runs ``ansible-playbook`` as a subprocess and turns its output into a
structured result.

Two non-real modes exist and are kept distinct:
  * ``check=True``   -> real Ansible run with ``--check --diff`` (talks to hosts);
  * simulation       -> Ansible is never started; used for ``dry_run`` settings
    and, optionally, when the binary is not installed. Simulated results are
    flagged ``simulated`` everywhere so they cannot be mistaken for real ones.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import Settings
from .exceptions import ExecutionError
from .inventory import InventoryBuilder
from .models import mask_secrets, now_iso

_RECAP_RE = re.compile(
    r"^(?P<host>\S+)\s*:\s*ok=(?P<ok>\d+)\s+changed=(?P<changed>\d+)\s+unreachable=(?P<unreachable>\d+)"
    r"\s+failed=(?P<failed>\d+)(?:\s+skipped=(?P<skipped>\d+))?(?:\s+rescued=(?P<rescued>\d+))?"
    r"(?:\s+ignored=(?P<ignored>\d+))?"
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class PlaybookResult:
    playbook: str
    rc: int
    duration: float
    recap: Dict[str, Dict[str, int]] = field(default_factory=dict)
    simulated: bool = False
    cancelled: bool = False
    timed_out: bool = False
    command: str = ""

    @property
    def failed_hosts(self) -> List[str]:
        return sorted(h for h, s in self.recap.items() if s.get("failed", 0) > 0)

    @property
    def unreachable_hosts(self) -> List[str]:
        return sorted(h for h, s in self.recap.items() if s.get("unreachable", 0) > 0)

    @property
    def ok_hosts(self) -> List[str]:
        bad = set(self.failed_hosts) | set(self.unreachable_hosts)
        return sorted(h for h in self.recap if h not in bad)

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.cancelled and not self.timed_out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook": self.playbook,
            "rc": self.rc,
            "duration_seconds": round(self.duration, 2),
            "recap": self.recap,
            "ok_hosts": self.ok_hosts,
            "failed_hosts": self.failed_hosts,
            "unreachable_hosts": self.unreachable_hosts,
            "simulated": self.simulated,
            "cancelled": self.cancelled,
            "timed_out": self.timed_out,
        }


def parse_recap(output_lines: List[str]) -> Dict[str, Dict[str, int]]:
    """Extract per-host counters from the PLAY RECAP block. With several
    recaps in one stream (should not happen) the last one wins."""
    recap: Dict[str, Dict[str, int]] = {}
    in_recap = False
    for raw in output_lines:
        line = _ANSI_RE.sub("", raw).rstrip()
        if line.startswith("PLAY RECAP"):
            in_recap = True
            continue
        if not in_recap:
            continue
        match = _RECAP_RE.match(line)
        if match:
            recap[match.group("host")] = {
                k: int(v or 0) for k, v in match.groupdict().items() if k != "host"
            }
    return recap


class AnsibleExecutor:
    def __init__(self, settings: Settings):
        self.settings = settings

    # ------------------------------------------------------------------
    def should_simulate(self, force: bool = False) -> bool:
        if force or self.settings.dry_run:
            return True
        if not self.settings.ansible_available():
            if self.settings.simulate_when_ansible_missing:
                return True
            raise ExecutionError(
                "%r not found in PATH. Install Ansible (pip install ansible-core) or run with --dry-run."
                % self.settings.ansible_playbook_bin
            )
        return False

    def build_command(self, playbook: Path, inventory: Path, vars_file: Optional[Path],
                      limit: Optional[List[str]], tags: Optional[List[str]], check: bool) -> List[str]:
        cmd = [self.settings.ansible_playbook_bin, "-i", str(inventory), str(playbook),
               "--forks", str(self.settings.ansible_forks)]
        if vars_file is not None:
            cmd += ["--extra-vars", "@%s" % vars_file]
        if limit:
            cmd += ["--limit", ",".join(limit)]
        if tags:
            cmd += ["--tags", ",".join(tags)]
        if check:
            cmd += ["--check", "--diff"]
        if self.settings.ansible_verbosity > 0:
            cmd.append("-" + "v" * min(self.settings.ansible_verbosity, 4))
        return cmd

    def _write_vars(self, run_id: str, extra_vars: Dict[str, Any]) -> Path:
        path = self.settings.vars_dir / ("%s.json" % run_id)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(extra_vars, handle)
        return path

    # ------------------------------------------------------------------
    def run(self, playbook: str, inventory: Path, run_id: str, extra_vars: Optional[Dict[str, Any]] = None,
            limit: Optional[List[str]] = None, tags: Optional[List[str]] = None, check: bool = False,
            log_path: Optional[Path] = None, cancel_event: Optional[threading.Event] = None,
            timeout: Optional[int] = None, simulate: bool = False,
            on_simulate: Optional[Callable[[List[str], Dict[str, Any]], None]] = None) -> PlaybookResult:
        """Run one playbook (path relative to ``ansible/playbooks``).

        ``on_simulate`` is called in simulation mode with the targeted hosts
        and the extra vars, so callers can fabricate the artefacts (reports)
        a real run would have produced.
        """
        playbook_path = self.settings.playbook_path(playbook)
        extra_vars = dict(extra_vars or {})
        simulate = self.should_simulate(force=simulate)
        vars_file = self._write_vars(run_id, extra_vars) if extra_vars else None
        cmd = self.build_command(playbook_path, inventory, vars_file, limit, tags, check)
        printable = " ".join(shlex.quote(c) for c in cmd)
        log = open(str(log_path), "a") if log_path else open(os.devnull, "w")
        started = time.time()
        try:
            log.write("\n===== [%s] %s =====\n$ %s\n" % (now_iso(), playbook, printable))
            log.write("extra_vars: %s\n" % json.dumps(mask_secrets(extra_vars), sort_keys=True))
            log.flush()

            if simulate:
                hosts = InventoryBuilder.hosts_in(inventory, limit)
                log.write("[SIMULATED] ansible-playbook was not executed. Target hosts: %s\n" % ", ".join(hosts))
                if on_simulate is not None:
                    on_simulate(hosts, extra_vars)
                recap = {h: {"ok": 1, "changed": 0, "unreachable": 0, "failed": 0, "skipped": 0,
                             "rescued": 0, "ignored": 0} for h in hosts}
                return PlaybookResult(playbook, 0, time.time() - started, recap, simulated=True, command=printable)

            return self._run_process(playbook, cmd, printable, log, started, cancel_event,
                                     timeout or self.settings.job_timeout_seconds)
        finally:
            log.close()
            if vars_file is not None:
                try:
                    vars_file.unlink()
                except OSError:
                    pass

    def _run_process(self, playbook: str, cmd: List[str], printable: str, log, started: float,
                     cancel_event: Optional[threading.Event], timeout: int) -> PlaybookResult:
        env = dict(os.environ)
        env.update({
            "ANSIBLE_CONFIG": str(self.settings.ansible_dir / "ansible.cfg"),
            "ANSIBLE_FORCE_COLOR": "0",
            "ANSIBLE_NOCOLOR": "1",
            "PYTHONUNBUFFERED": "1",
        })
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(self.settings.ansible_dir), env=env, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1,
            )
        except OSError as exc:
            raise ExecutionError("could not start ansible-playbook: %s" % exc)

        lines: List[str] = []

        def pump() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                lines.append(line)
                log.write(line)
                log.flush()

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()

        cancelled = timed_out = False
        while proc.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                cancelled = True
            elif time.time() - started > timeout:
                timed_out = True
            if cancelled or timed_out:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                break
            time.sleep(0.25)
        proc.wait()
        reader.join(timeout=5)

        if cancelled:
            log.write("\n[CANCELLED] playbook terminated on request\n")
        if timed_out:
            log.write("\n[TIMEOUT] playbook exceeded %ss and was terminated\n" % timeout)
        return PlaybookResult(
            playbook=playbook, rc=proc.returncode if proc.returncode is not None else -1,
            duration=time.time() - started, recap=parse_recap(lines), cancelled=cancelled,
            timed_out=timed_out, command=printable,
        )
