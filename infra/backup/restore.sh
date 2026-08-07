#!/usr/bin/env bash
# MBS.SC -- restore + verify a backup into a CLEAN target database (Phase 1.1).
# Implements the disaster-recovery drill: clean DB -> restore -> migrations -> smoke.
# Never restores over the live DB unless you explicitly point --target-db at it.
# See docs/runbooks/backup-restore.md.
#
#   restore.sh --backup <dir> [--target-db mbs_restore] [--objects] [--alembic-docker <api_container>]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

BACKUP_DIR=""; TARGET_DB="mbs_restore"; DO_OBJECTS=0; ALEMBIC_DOCKER=""
: "${PGHOST:=localhost}"; : "${PGPORT:=5432}"; : "${PGUSER:=mbs}"; : "${MBS_PG_DOCKER:=}"
usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do case "$1" in
  --backup) BACKUP_DIR="$2"; shift 2;;
  --target-db) TARGET_DB="$2"; shift 2;;
  --objects) DO_OBJECTS=1; shift;;
  --alembic-docker) ALEMBIC_DOCKER="$2"; shift 2;;
  -h|--help) usage;;
  *) echo "unknown arg: $1"; usage;;
esac; done
[ -n "${BACKUP_DIR}" ] && [ -f "${BACKUP_DIR}/db.dump" ] || { echo "ERROR: --backup <dir> with db.dump required"; usage; }

_psql() { if [ -n "${MBS_PG_DOCKER}" ]; then docker exec -i "${MBS_PG_DOCKER}" psql -U "${PGUSER}" "$@"; else PGPASSWORD="${PGPASSWORD:-}" psql -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" "$@"; fi; }
_pgrestore() { if [ -n "${MBS_PG_DOCKER}" ]; then docker exec -i "${MBS_PG_DOCKER}" pg_restore -U "${PGUSER}" "$@"; else PGPASSWORD="${PGPASSWORD:-}" pg_restore -h "${PGHOST}" -p "${PGPORT}" -U "${PGUSER}" "$@"; fi; }

echo "[restore] step 1/5: clean target database '${TARGET_DB}'"
_psql -d postgres -c "DROP DATABASE IF EXISTS ${TARGET_DB};"
_psql -d postgres -c "CREATE DATABASE ${TARGET_DB};"

echo "[restore] step 2/5: restore db.dump -> ${TARGET_DB}"
_pgrestore -d "${TARGET_DB}" --no-owner --no-privileges < "${BACKUP_DIR}/db.dump"

echo "[restore] step 3/5: run migrations (compatibility check; should already be at head)"
FRESH_URL="postgresql+asyncpg://${PGUSER}:${PGPASSWORD:-mbs}@${PGHOST}:${PGPORT}/${TARGET_DB}"
if [ -n "${ALEMBIC_DOCKER}" ]; then
  # In the compose deployment the app image carries alembic; restored DB reachable as
  # host 'postgres' from inside the app network.
  docker exec -e DATABASE_URL="postgresql+asyncpg://${PGUSER}:${PGPASSWORD:-mbs}@postgres:5432/${TARGET_DB}" \
    "${ALEMBIC_DOCKER}" sh -lc 'cd /srv/db && alembic current && alembic upgrade head && alembic current'
else
  ( cd "${HERE}/../../db" && DATABASE_URL="${FRESH_URL}" alembic current && DATABASE_URL="${FRESH_URL}" alembic upgrade head )
fi

echo "[restore] step 4/5: smoke checks (schema, RLS, data present)"
_psql -d "${TARGET_DB}" -tc "SELECT 'tables='||count(*) FROM information_schema.tables WHERE table_schema='public';"
_psql -d "${TARGET_DB}" -tc "SELECT 'rls_policies='||count(*) FROM pg_policies;"
_psql -d "${TARGET_DB}" -tc "SELECT 'force_rls_tables='||count(*) FROM pg_class WHERE relkind='r' AND relforcerowsecurity;"
_psql -d "${TARGET_DB}" -tc "SELECT 'users='||count(*) FROM users;" || echo "[restore] (users table absent?)"

echo "[restore] step 5/5: object storage"
if [ "${DO_OBJECTS}" = "1" ] && [ -d "${BACKUP_DIR}/objects" ]; then
  python3 "${HERE}/object_store.py" verify "${BACKUP_DIR}/objects"
  echo "[restore] uploading objects back (set target endpoint via S3_* env)"
  python3 "${HERE}/object_store.py" restore "${BACKUP_DIR}/objects"
else
  echo "[restore] object restore skipped (--objects not set or no objects/ dir)"
fi

echo "[restore] DONE. Verify the application starts against '${TARGET_DB}' before switching traffic."
