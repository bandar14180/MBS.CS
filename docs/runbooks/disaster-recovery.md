# Disaster Recovery Runbook (Phase 1.6)

Automated, configurable backup & restore for PostgreSQL **and** object storage (evidence +
reports), with verification, retention, metrics, and structured logging. This complements
the manual `infra/backup/*.sh` scripts (Phase 1.1) with a testable, scheduled, in-app system.

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

## CLI
```bash
python -m apps.api.dr backup                    # create + verify + prune  (exit 0/1)
python -m apps.api.dr verify   <set_dir>        # integrity + checksum      (exit 0/1)
python -m apps.api.dr restore  <set_dir> [--target-db-url URL] [--objects]
python -m apps.api.dr cleanup                   # apply retention now
```
Exit code is `0` on success, non-zero on failure — composes with cron/systemd/CI.

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
