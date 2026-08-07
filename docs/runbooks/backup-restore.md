# Runbook: Backup & Restore (Disaster Recovery)

Phase 1.1 production hardening. **A backup is only "done" when a restore has been proven.**
This runbook + the scripts in `infra/backup/` provide an automated backup and a tested
restore drill for the two stateful stores: **PostgreSQL** and **object storage (MinIO/S3)**.

Redis is a broker/cache only (queue + rate-limit + DLQ) and is intentionally **not**
backed up — jobs are idempotent and re-runnable, and the DLQ is inspect/replay tooling,
not a source of truth.

---

## 1. Backup architecture

```
                 infra/backup/backup.sh
                          |
        +-----------------+------------------+
        |                                    |
   pg_dump -Fc                        object_store.py (boto3)
   (custom format:                    download every object in
    compressed, selective/            mbs-evidence + mbs-reports
    parallel restore)                        |
        |                                    |
   db.dump  +  db.toc (validated)      objects/<bucket>/<key> + CHECKSUMS.sha256
        \____________________  ________________/
                             \/
        backups/<UTC-timestamp>/  { db.dump, db.toc, objects/, CHECKSUMS.sha256, MANIFEST.txt, objects.json }
```

- **PostgreSQL:** `pg_dump -Fc` (custom format) — compressed, migration-consistent (the
  dump includes `alembic_version`, so a restore lands exactly at the schema head), and
  supports selective/parallel `pg_restore`. Each backup is validated immediately with
  `pg_restore --list` (fails fast on a corrupt/truncated dump).
- **Object storage:** every object in `mbs-evidence` (raw tool output / evidence) and
  `mbs-reports` (generated PDFs) is downloaded and SHA-256 checksummed.
- **Integrity:** `CHECKSUMS.sha256` covers `db.dump`, `db.toc`, and every object;
  `MANIFEST.txt` records timestamp, dump size, table-data section count, and git head.
- **Security:** credentials come only from env or `*_FILE` indirection (Docker
  Secrets/Vault-ready) — never CLI args. The scripts read the DB and object storage;
  they never touch the application, schema, RBAC, or RLS.

## 2. Configuration & schedule

Environment (defaults match `infra/docker-compose.yml`):

| Var | Default | Purpose |
|---|---|---|
| `BACKUP_ROOT` | `infra/backup/backups` | destination root |
| `RETENTION_DAYS` | `7` | prune whole backup sets older than N days |
| `PGHOST/PGPORT/PGUSER/PGDATABASE` | `localhost/5432/mbs/mbs` | DB connection |
| `PGPASSWORD` (or `PGPASSWORD_FILE`) | — | DB password (prod) |
| `MBS_PG_DOCKER` | — | run `pg_dump`/`psql`/`pg_restore` inside this container (dev/compose) |
| `S3_ENDPOINT_URL`, `S3_ACCESS_KEY(_FILE)`, `S3_SECRET_KEY(_FILE)`, `S3_BUCKET_EVIDENCE`, `S3_BUCKET_REPORTS` | MinIO defaults | object storage |

**Scheduling (choose one; deliberately no bundled scheduler container):**

- Host cron (recommended): `15 2 * * *  BACKUP_ROOT=/var/backups/mbs RETENTION_DAYS=14 /opt/mbs/infra/backup/backup.sh >> /var/log/mbs-backup.log 2>&1`
- systemd timer, or a CI/CD scheduled job that runs `backup.sh` in a maintenance
  container (needs `postgres-client` + `python3-boto3`) with `BACKUP_ROOT` on a durable,
  **off-host** volume (S3/NFS). Encrypt at rest and restrict access to the backup store.

## 3. Retention policy

Default 7 days of full sets (`RETENTION_DAYS`). Recommended production: 14–30 daily +
weekly/monthly promotion to cold storage, with off-site copies. Backups are self-contained
sets, so retention is a simple directory prune.

## 4. Restore steps (the drill)

`restore.sh` performs: **clean DB → restore → migrations (compatibility check) → smoke**.

```
infra/backup/restore.sh \
  --backup infra/backup/backups/<timestamp> \
  --target-db mbs_restore \
  --objects \
  --alembic-docker infra-api-1     # (compose) run migrations via the app image
```

Steps executed:
1. `DROP DATABASE IF EXISTS <target>; CREATE DATABASE <target>;` (never overwrites live unless you name it).
2. `pg_restore --no-owner --no-privileges -d <target> db.dump`.
3. `alembic current` → `alembic upgrade head` → `alembic current` — must be a **no-op at
   the head** (proves the backup is migration-consistent).
4. Smoke: table count, RLS policy count, FORCE-RLS table count, a data-presence check.
5. Object storage: `object_store.py verify` (checksums) then `restore` (upload back to the
   target endpoint — point `S3_*` at the restore target so you never clobber production).

**Cutover:** start the app against `<target>` (set `DATABASE_URL`) and hit `/ready`
before switching traffic. Then rename/promote the restored DB during a maintenance window.

## 5. Common failure scenarios

| Symptom | Likely cause | Action |
|---|---|---|
| `pg_restore --list` fails in backup | truncated/corrupt dump (disk full, killed) | backup aborts by design; fix space, re-run |
| Restore: role/owner errors | dump made as a different role | already handled via `--no-owner --no-privileges` |
| `alembic upgrade head` applies a migration | backup predates a schema change | expected only for old backups; verify app compatibility |
| Object `verify` mismatch | corrupt/incomplete object copy | re-run object backup; investigate storage |
| RLS policy count = 0 after restore | restored as superuser without policies? | `pg_dump` includes policies; check the dump/toc |
| App `/ready` 503 after restore | wrong `DATABASE_URL`/creds, deps down | fix env; check Postgres/Redis/MinIO |

## 6. Recovery checklist

- [ ] Latest backup set present; `MANIFEST.txt` + `CHECKSUMS.sha256` valid.
- [ ] `pg_restore --list db.dump` succeeds.
- [ ] Restore into a **clean** target DB succeeds.
- [ ] `alembic current` == head; `alembic upgrade head` is a no-op.
- [ ] Smoke: expected tables, RLS policies (>0), FORCE-RLS tables present, data rows present.
- [ ] Object `verify` = 0 mismatches; objects restored to the target endpoint.
- [ ] App starts against the restored DB; `/ready` green.
- [ ] Cutover during a maintenance window; keep the previous DB until verified.

## 7. Scope / limitations

- Additive, reversible tooling only (delete `infra/backup/` + this runbook to remove).
- No app/API/security/RLS changes.
- Dev note: in the compose stack the DB tools live in the postgres container and
  `boto3`/`alembic` in the app image, so use `MBS_PG_DOCKER` / `--alembic-docker`. On a
  production backup host install `postgres-client` + `python3-boto3` and run natively.
- Encryption-at-rest of the backup store and off-site replication are deployment
  responsibilities (documented above), not part of these scripts.
