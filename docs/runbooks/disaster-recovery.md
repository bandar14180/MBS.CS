# Disaster Recovery Runbook (Phase 1.6)

Automated, configurable backup & restore for PostgreSQL **and** object storage (evidence +
reports), with verification, retention, metrics, and structured logging.

**`apps/api/dr/` is the production backup system** — it is what `worker-default` runs on the
beat schedule (`backup.run`) and what `docker-compose.prod.yml` configures. It superseded the
manual `infra/backup/*.sh` shell scripts (Phase 1.1), which were never wired into compose, CI
or the scheduler and have been removed; this runbook is the single source of truth. If you
find a reference to `infra/backup/` or `backup-restore.md` anywhere, it is stale.

## Layout of a backup set
Each run creates one **timestamped, never-overwritten** directory under `BACKUP_DIRECTORY`:

```
<BACKUP_DIRECTORY>/20260807T031500Z/
  db.dump                 # pg_dump -Fc (compressed custom format, 'PGDMP' magic)
  db.dump.sha256
  objects.tar.gz          # every bucket's objects in one gzip'd tar
  objects.meta.json       # per-object content-type + user metadata (faithful restore)
  objects.tar.gz.sha256
  MANIFEST.json           # timestamp, per-component result + checksums, overall status
```

## CLI — operator quick reference
```bash
python -m apps.api.dr backup                    # create + verify + prune  (exit 0/1)
python -m apps.api.dr verify   <set_dir>        # integrity + checksum      (exit 0/1)
python -m apps.api.dr drill    --target-db-url <SCRATCH_DB> [--set <dir>] [--objects]
python -m apps.api.dr restore  <set_dir> [--target-db-url URL] [--objects]
python -m apps.api.dr cleanup                   # apply retention now
```
Exit code is `0` on success, non-zero on failure — composes with cron/systemd/CI.

Run these on **`worker-default`**: it is the service that mounts `backup_data:/srv/backups`
(`BACKUP_DIRECTORY`), so a set created anywhere else is written to container-local storage and
lost on recreation. The image also ships the postgres client that `pg_dump`/`pg_restore` need.

```bash
COMPOSE="-f infra/docker-compose.yml -f infra/docker-compose.prod.yml"
docker compose $COMPOSE exec worker-default python -m apps.api.dr backup
docker compose $COMPOSE exec worker-default python -m apps.api.dr verify /srv/backups/<SET>
```

`restore` and `drill` write to a database. `drill` refuses to run without a scratch target and
refuses a target equal to the live `DATABASE_URL`; `restore` has **no such guard** — always pass
`--target-db-url` explicitly unless you intend to overwrite the database in `DATABASE_URL`.

## Backup flow
1. `pg_dump -Fc` → `db.dump`; reject a missing/tiny/non-`PGDMP` archive; write `.sha256`.
2. Stream all buckets → `objects.tar.gz` + `objects.meta.json`; write `.sha256`.
3. Write `MANIFEST.json` (`completed` / `failed`).
4. If `BACKUP_VERIFICATION_ENABLED`, verify the set (below).
5. Retention cleanup.

A component failure is recorded in the manifest and metrics **without** aborting the others.

## Restore flow
1. Verify the set exists and (if verification enabled) **passes** before mutating anything.
2. `pg_restore --no-owner --no-privileges` into the target DB (`--target-db-url` to restore
   into a scratch DB — do a DR drill against a clean DB, never over live data by default).
3. `--objects` re-uploads every object, re-applying preserved content-type + metadata.

## Verification flow (never touches production data)
- **PostgreSQL:** `db.dump` exists, non-trivial, starts with `PGDMP`, checksum matches.
- **Objects:** manifest + archive present, the gzip/tar fully reads (CRC → corruption
  detection), and the member count matches the manifest.

## Retention / cleanup
Age-based (`BACKUP_RETENTION_DAYS`) but it **always keeps the newest `max(BACKUP_MIN_KEEP,1)`
sets** and **never deletes the newest** — a burst of failures can't erase the last good
backup. Deletions are logged.

## Scheduling
Set `BACKUP_ENABLED=true` to register a beat entry (`backup.run`, every
`BACKUP_INTERVAL_SECONDS`) on the **default** Celery queue — never the `scans` queue, so it
does not interfere with scan execution. Disabled by default (no beat tick when off).

## Metrics (low-cardinality label `component` ∈ {postgres, objects, full})
`mbs_backup_success_total`, `mbs_backup_failed_total`, `mbs_backup_duration_seconds`,
`mbs_restore_success_total`, `mbs_restore_failed_total`, `mbs_verification_success_total`,
`mbs_verification_failed_total`. No hostname / filename / workspace_id / scan_id labels.

## Configuration
`BACKUP_ENABLED`, `BACKUP_DIRECTORY`, `BACKUP_INTERVAL_SECONDS`, `BACKUP_RETENTION_DAYS`,
`BACKUP_MIN_KEEP`, `BACKUP_INCLUDE_OBJECTS`, `BACKUP_COMPRESSION`,
`BACKUP_VERIFICATION_ENABLED`, `BACKUP_PG_DUMP_CMD`, `BACKUP_PG_RESTORE_CMD`.

## Deployment note
The runtime must have the postgres client (`pg_dump`/`pg_restore`) on `PATH`, or point
`BACKUP_PG_DUMP_CMD` / `BACKUP_PG_RESTORE_CMD` at an absolute path / wrapper. Object storage
uses the app's existing `S3_*` credentials (never logged, never passed on argv).

---

# Production hardening (DR-1 … DR-4)

All additive, feature-flagged, and default-OFF. Enabling them does not change the set layout or
the CLI above; encryption/off-site are transparent to `verify`/`restore`.

## DR-1 — Durable backup storage
`worker-default` (which runs `backup.run`) mounts the **`backup_data` named volume** at
`/srv/backups`, so backup sets **survive container recreation/redeploy**. The production overlay
sets `BACKUP_ENABLED=true` (and gives `beat` the same flag so it registers the tick). Bind
`backup_data` to a durable/off-host path for real deployments, and pair with DR-3.

## DR-2 — Encryption at rest (AES-256-GCM)
`BACKUP_ENCRYPTION_ENABLED=true` encrypts each set's `db.dump` + `objects.tar.gz` **in place**
(same filenames; content becomes ciphertext with an `MBSENC1` header). The key is derived from
`BACKUP_ENCRYPTION_KEY` (supports `BACKUP_ENCRYPTION_KEY_FILE` — Docker Secrets / Vault).
`verify`/`restore` decrypt transparently; a **wrong key fails closed** (GCM tag mismatch →
verification returns false, restore aborts). Existing unencrypted sets stay readable. Production
must set the key (enforced by `validate_production`). Config: `BACKUP_ENCRYPTION_ENABLED`,
`BACKUP_ENCRYPTION_KEY(_FILE)`.

## DR-3 — Off-site replication (provider-agnostic)
After a **verified** set, `BACKUP_OFFSITE_ENABLED=true` replicates it off-host. Providers:
`local` (copy to a mounted/off-host dir, `BACKUP_OFFSITE_DIR`) or `s3` (upload to **any**
S3-compatible endpoint — AWS/MinIO/Wasabi/B2 — via `BACKUP_OFFSITE_BUCKET`,
`BACKUP_OFFSITE_PREFIX`, `BACKUP_OFFSITE_ENDPOINT_URL`, and credentials that fall back to the
app's `S3_*`). Best-effort: a replication failure is metered (`mbs_backup_offsite_failed_total`)
but never fails the backup. Extend by implementing `OffsiteTarget` in `apps/api/dr/offsite.py`.

## DR-4 — Reliability monitoring + recovery evidence
- **Freshness:** each successful backup stamps a Redis timestamp; the API `/metrics`
  `ReliabilityCollector` exposes **`mbs_backup_age_seconds`**. Alert **`MbsBackupStale`**
  (`> 30h`) catches a silently stalled pipeline (metrics counters: also
  `mbs_backup_offsite_*`, `mbs_dr_drill_*`).
- **Manual DR drill (evidence):**
  ```bash
  python -m apps.api.dr drill [--set <set_dir>] --target-db-url <SCRATCH_DB> [--objects]
  ```
  Restores the latest (or given) **verified** set into a **scratch** DB (refuses the live
  `DATABASE_URL`), runs smoke checks (connect, tables, RLS policies, FORCE-RLS tables), and
  writes a JSON **evidence artifact** to `<BACKUP_DIRECTORY>/drills/drill-<ts>.json`. Exit
  `0`/`1`. Restore drills are **not auto-scheduled** at this stage (run in CI/cron manually).
  Config: `BACKUP_DRILL_DATABASE_URL` (optional default scratch target).

## R1a — Durable Redis (broker / DLQ / operational state)
Redis backs the Celery **broker + result backend**, the scan **dead-letter queue**
(`dlq:scans.run_scan`), the **rate-limit** / **AI-budget** / **MFA-lockout** counters, and the
**reliability freshness** timestamps (`mbs_backup_age_seconds`, `mbs_beat_age_seconds`).
Previously these lived only in RAM (default RDB wrote to an **unmounted** `/data`), so any Redis
restart dropped the queue, the DLQ backlog, and those counters. R1a enables **AOF**
(`--appendonly yes --appendfsync everysec`) and mounts `/data` on the durable **`redis_data`**
named volume, so this state **survives a restart**. No `maxmemory` is set (default = no eviction),
so broker/DLQ entries are never evicted. Consumer behavior is unchanged — all Redis paths are
idempotent (DLQ replay is safe via the atomic scan claim + orphan reaper) or fail-open
(rate-limit / budget / MFA-lockout). For a real deployment, bind `redis_data` to a durable/off-host
path. *(This is single-node durability, not HA — Redis failover/replication is deferred; see DR-5.)*

## Recovery evidence — status

**No backup has been created and no restore drill has been executed in any environment yet.**
The mechanisms below are implemented and unit-tested (the DR suites use an injected fake
`PgRunner`/object store, so they exercise the naming, checksum, verification, retention and
drill-safety logic — **not** real `pg_dump`/`pg_restore`). Recoverability is therefore
**unproven** until a real backup set and a drill evidence artifact exist.

Closing that gap is the top DR priority: run `dr backup`, then `dr drill` against a scratch
database, and keep `<BACKUP_DIRECTORY>/drills/drill-<ts>.json` as the evidence. Until then,
treat the scenarios below as *designed* recovery paths, not *demonstrated* ones — and do not
enable live retention deletion (see `retention.md`, Stage 2), which depends on a restorable
backup existing.

### The four required scenarios
- **Database loss** → `dr restore` / `dr drill` (pg_restore into a clean DB; migration-consistent).
- **Object storage failure** → object verify + `restore --objects` (faithful metadata).
- **Accidental data deletion** → timestamped retained sets (`min_keep` never erases the newest);
  restore point-in-time-of-backup. *(MinIO versioning/object-lock recommended — see DR-5.)*
- **Infrastructure failure** → durable volumes (DR-1 backups, R1a Redis) + off-site copy (DR-3)
  survive host loss.

## DR-5 — Future production evolution (NOT implemented)
Deferred, larger-scope items for a future phase:
- **PITR** — PostgreSQL WAL archiving + base backups to shrink RPO from the dump interval (~24h)
  toward minutes/seconds. Requires archive storage + a WAL pipeline (e.g. pgBackRest/wal-g).
- **MinIO versioning + object-lock (WORM)** — defend the live buckets against accidental
  deletion/ransomware directly, independent of the periodic backup.
- **Scheduled automated restore drills** — promote the manual `dr drill` to a gated periodic job
  once a dedicated scratch environment exists.
- **RTO/RPO targets** — formalize and measure during drills.
