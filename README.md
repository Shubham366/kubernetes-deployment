# Linux Provisioning Backend

A Python backend that provisions and operates multi-node Linux clusters through
Ansible. Execution always starts from `main.py` (CLI or REST API); Python
validates the request, generates an inventory for the cluster, and runs the
matching playbooks as tracked jobs.

What it covers:

| Area | Controller | Playbooks / scripts |
|---|---|---|
| Clusters and nodes (register, ping, facts, OS bootstrap) | `cluster_controller.py` | `ansible/playbooks/cluster/` |
| Technology versions: Java, Python, Node.js, Go, Docker | `version_controller.py` | `ansible/playbooks/versions/*.yml` |
| Clustered software: Hadoop (standard / HA), Redis (standalone / replication / Sentinel / Cluster), PostgreSQL (standalone / streaming replication) | `software_controller.py` | `ansible/playbooks/software/*.yml`, `ansible/roles/{hadoop,redis,postgresql}` |
| Scanning: pending and security updates, compliance checks, inventory | `scan_controller.py` | `ansible/playbooks/scanning/scan.yml`, `ansible/scripts/scan/scan_{ubuntu,centos,rhel}.sh` |
| Patching: security / all / selected packages, rolling / canary, reboot policy, rollback | `patch_controller.py` | `ansible/playbooks/patching/*.yml`, `ansible/scripts/patch/patch_{ubuntu,centos,rhel}.sh` |

Supported targets: Ubuntu and Debian, CentOS / Rocky / AlmaLinux / Oracle Linux,
and RHEL. A single cluster can mix them.

## Requirements

- Python 3.9+ on the controller. The backend uses only the standard library.
- `ansible-core` 2.15+ on the controller for real runs (`pip install -r requirements.txt`).
  Only `ansible.builtin` modules are used, so no collections are needed.
- SSH access with sudo from the controller to every node.

Without Ansible installed, use `--dry-run`: every job is simulated and logged,
and no host is contacted.

## Quick start

```bash
# 1. register a cluster (10 nodes, mixed Ubuntu / CentOS / RHEL)
python main.py cluster create -f examples/cluster_mixed.json

# 2. check connectivity, detect the real OS, apply the OS baseline
python main.py cluster ping analytics
python main.py cluster facts analytics
python main.py cluster bootstrap analytics --var bootstrap_timezone=UTC

# 3. install a technology version on some or all nodes
python main.py version install analytics --technology java --version 17
python main.py version install analytics --technology python --version 3.11.9 --nodes an-db-01 an-db-02

# 4. deploy clustered software
python main.py software plan   analytics hadoop -f examples/hadoop_ha.json
python main.py software deploy analytics hadoop -f examples/hadoop_ha.json
python main.py software deploy analytics postgresql -f examples/postgresql_replication.json
python main.py software deploy analytics redis -f examples/redis_sentinel.json
python main.py software action analytics hadoop status
python main.py software action analytics hadoop scale_out -f examples/hadoop_scale_out.json

# 5. scan, review, patch
python main.py scan run analytics
python main.py scan latest analytics
python main.py patch plan  analytics -f examples/patch_rolling.json
python main.py patch apply analytics -f examples/patch_rolling.json
python main.py patch rollback <patch_id>

# jobs
python main.py job list
python main.py job log <job_id> --tail 100
```

Put `--dry-run` right after `main.py` to simulate any of these.
Job commands wait for completion and exit `0` on success, `2` if the job did
not succeed, `1` for a rejected request.

## REST API

```bash
PROVISIONER_API_TOKEN=change-me python main.py serve --host 0.0.0.0 --port 8080
```

Every mutating call returns `202` with a job; poll `/api/v1/jobs/<id>`.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness, Ansible availability |
| GET | `/api/v1/catalog` | technologies and software with versions and modes |
| GET, POST | `/api/v1/clusters` | list / create |
| GET, DELETE | `/api/v1/clusters/{c}` | show / delete (`?force=true`) |
| POST | `/api/v1/clusters/{c}/nodes` | add nodes |
| PATCH, DELETE | `/api/v1/clusters/{c}/nodes/{n}` | update / remove a node |
| POST | `/api/v1/clusters/{c}/ping`, `/facts`, `/bootstrap` | cluster operations |
| GET, POST | `/api/v1/clusters/{c}/versions` | installed technologies / install |
| DELETE | `/api/v1/clusters/{c}/versions/{technology}` | uninstall |
| GET | `/api/v1/clusters/{c}/software` | deployed software |
| POST | `/api/v1/clusters/{c}/software/{name}/plan` | validate and preview a layout |
| POST | `/api/v1/clusters/{c}/software/{name}` | deploy |
| POST | `/api/v1/clusters/{c}/software/{name}/actions/{action}` | start, stop, restart, status, scale_out, decommission, add_replica, promote, uninstall |
| GET, POST | `/api/v1/clusters/{c}/scans` | scan history / start a scan |
| GET | `/api/v1/clusters/{c}/scans/latest` | latest results (`?reports=true`) |
| GET | `/api/v1/scans/{id}`, `/compliance`, `/diff/{other}` | results, compliance matrix, diff |
| POST | `/api/v1/clusters/{c}/patches/plan` | preview a patch run |
| GET, POST | `/api/v1/clusters/{c}/patches` | patch history / apply |
| GET | `/api/v1/patches/{id}` | patch results |
| POST | `/api/v1/patches/{id}/rollback` | roll back |
| GET | `/api/v1/jobs`, `/jobs/{id}`, `/jobs/{id}/log` | jobs |
| POST | `/api/v1/jobs/{id}/cancel` | cancel |

Set `api_token` whenever the API listens on anything but localhost: whoever can
reach it can run playbooks as root on your machines.

## How it works

```
main.py ──> controllers ──> JobManager ──> AnsibleExecutor ──> ansible-playbook
               │                │                                   │
               │                └── inventory JSON per job          └── roles / scripts
               └── catalog.py (versions, OS compatibility, topology rules)
            Store (SQLite): clusters, nodes, jobs, scan/patch results, installations
```

- **Inventory** (`provisioner/inventory.py`): generated per job. Each node role
  becomes a group of the same name (`hadoop_namenode`, `redis_master`,
  `postgresql_primary`, ...), plus `os_<type>`, `family_<family>` and label groups.
- **Jobs** (`provisioner/jobs.py`): a job is an ordered list of playbook steps.
  Jobs on the same cluster run one at a time; different clusters run in
  parallel. Status is `success`, `partial` (some hosts failed), `failed`,
  `cancelled` or `interrupted` (backend restarted mid-job).
- **Versions**: the install method is resolved per node before anything runs
  (for example JDK 21 comes from packages on Ubuntu 22.04 but from the Temurin
  tarball on CentOS 7), and one step runs per method. Impossible combinations
  (Node.js 20 on EL7) are rejected up front.
- **Software**: the role layout is validated before deployment (quorum sizes,
  replication factor vs. DataNode count, Redis Cluster minimum size, PostgreSQL
  version vs. OS). If no layout is given one is proposed from the node pool.
  Generated passwords are stored with the installation and reused on re-runs.
- **Scanning**: a distro-specific script writes one JSON report per host; the
  controller validates, scores (0-100 risk) and stores them. Hosts without a
  usable report make the scan `partial`, never silently green.
- **Patching**: hosts are patched in tiers (standalone hosts, then
  workers/replicas, then primaries, primaries one at a time). A later tier runs
  only if the earlier ones were clean. `all_at_once` with reboots is refused on
  nodes running clustered software unless `force` is set.

## Configuration

Defaults, then a JSON file (`--config` or `PROVISIONER_CONFIG`), then
`PROVISIONER_<SETTING>` environment variables, then CLI flags.

| Setting | Default | Meaning |
|---|---|---|
| `data_dir` | `./data` | database, logs, inventories, reports |
| `ansible_dir` | `./ansible` | playbooks, roles, scripts |
| `dry_run` | `false` | simulate all runs |
| `simulate_when_ansible_missing` | `false` | simulate instead of failing when Ansible is absent |
| `max_workers` | `4` | clusters worked on in parallel |
| `ansible_forks` | `20` | hosts in parallel per playbook |
| `job_timeout_seconds` | `14400` | per playbook |
| `api_host`, `api_port`, `api_token` | `127.0.0.1`, `8080`, empty | REST API |

## Things to know

- Deployment variables, including generated passwords, are stored unencrypted in
  `data/provisioner.db`. They are masked in API responses, job records and logs,
  but protect the data directory.
- Deleting a cluster only removes the record; it does not uninstall anything.
- `--dry-run` writes placeholder scan and patch reports flagged `simulated`.
  They describe no real machine.
- `purge_data` on uninstall deletes data directories and needs `confirm_purge`.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests run the whole backend in dry-run mode; they do not execute playbooks
against hosts.
