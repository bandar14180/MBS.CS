#!/usr/bin/env bash
# MBS.SC -- PostgreSQL + object-storage backup (Phase 1.1). Additive & reversible: it
# reads the database and object storage; it never modifies the application, schema, or
# security config. See docs/runbooks/backup-restore.md.
#
# Config (env; credentials via env or *_FILE, NEVER CLI args):
#   BACKUP_ROOT      backup destination root        (default: infra/backup/backups)
#   RETENTION_DAYS   prune backups older than N days (default: 7)
#   PGHOST/PGPORT/PGUSER/PGDATABASE/PGPASSWORD      (defaults: localhost/5432/mbs/mbs)
#   MBS_PG_DOCKER    optional: run pg_dump inside this container (dev/compose convenience)
#   S3_* (see object_store.py)                       object-storage endpoint + creds
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${BACKUP_ROOT:=${HERE}/backups}"
: "${RETENTION_DAYS:=7}"
: "${PGHOST:=localhost}"; : "${PGPORT:=5432}"; : "${PGUSER:=mbs}"; : "${PGDATABASE:=mbs}"
: "${MBS_PG_DOCKER:=}"
: "${SKIP_OBJECTS:=0}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
DIR="${BACKUP_ROOT}/${TS}"
mkdir -p "${DIR}"
echo "[backup] ${TS} -> ${DIR} (db=${PGDATABASE})"

_pgdump() {
  if [ -n "${MBS_PG_DOCKER}" ]; then
    docker exec "${MBS_PG_DOCKER}" pg_dump -U "${PGUSER}" -d "${PGDATABASE}" -Fc
  else
    PGPASSWORD="${PGPASSWORD:-}" pg_dump -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" -d "${PGDATABASE}" -Fc
  fi
}
_pglist() {  # validate the dump is a readable custom-format archive
  if [ -n "${MBS_PG_DOCKER}" ]; then docker exec -i "${MBS_PG_DOCKER}" pg_restore --list; else pg_restore --list "${DIR}/db.dump"; fi
}

# 1) Database dump: custom format (-Fc) = compressed, supports selective/parallel restore.
_pgdump > "${DIR}/db.dump"

# 2) Validate the dump (fail the backup if it is corrupt / truncated).
if [ -n "${MBS_PG_DOCKER}" ]; then _pglist < "${DIR}/db.dump" > "${DIR}/db.toc"; else _pglist > "${DIR}/db.toc"; fi
DUMP_BYTES="$(wc -c < "${DIR}/db.dump" | tr -d ' ')"
TABLE_DATA="$(grep -c 'TABLE DATA' "${DIR}/db.toc" || true)"
if [ "${DUMP_BYTES}" -lt 1000 ]; then echo "[backup] ERROR: db.dump too small (${DUMP_BYTES} bytes)"; exit 1; fi
echo "[backup] db.dump=${DUMP_BYTES} bytes, ${TABLE_DATA} table-data sections"

# 3) Object storage (evidence + reports). boto3, portable MinIO/S3.
if [ "${SKIP_OBJECTS}" != "1" ]; then
  python3 "${HERE}/object_store.py" backup "${DIR}/objects" | tee "${DIR}/objects.json"
else
  echo '{"skipped":true}' > "${DIR}/objects.json"
fi

# 4) Checksums + manifest (integrity + provenance).
( cd "${DIR}" && sha256sum db.dump db.toc >> CHECKSUMS.sha256 )
{
  echo "timestamp=${TS}"
  echo "database=${PGDATABASE}"
  echo "dump_bytes=${DUMP_BYTES}"
  echo "table_data_sections=${TABLE_DATA}"
  echo "git_head=$(git -C "${HERE}" rev-parse --short HEAD 2>/dev/null || echo n/a)"
  echo "created_by=$(id -un 2>/dev/null || echo unknown)"
} > "${DIR}/MANIFEST.txt"

# 5) Retention: prune whole backup sets older than RETENTION_DAYS.
find "${BACKUP_ROOT}" -maxdepth 1 -type d -name '20*' -mtime "+${RETENTION_DAYS}" -exec rm -rf {} + 2>/dev/null || true

echo "[backup] OK -> ${DIR}"
