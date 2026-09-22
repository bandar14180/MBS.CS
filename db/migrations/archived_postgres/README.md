# Archived Postgres migrations (pre Phase 0 MySQL cutover)

These 21 files are the Postgres-targeted Alembic migrations that built up this project's
schema before the MySQL cutover. They are **not part of the active migration chain** --
Alembic only scans `db/migrations/versions/`, not this directory, so nothing here runs or is
even imported by `alembic upgrade head`. They are kept for historical reference only: to see
*why* a table or column looks the way it does, or to recover a piece of Postgres-specific
logic (an RLS policy's exact `USING` clause, a data backfill) that the MySQL baseline
intentionally did not carry forward.

**Do not run these against a live database.** They target `sqlalchemy.dialects.postgresql`
types (`UUID`, `JSONB`) and Postgres-only DDL (`ENABLE/FORCE ROW LEVEL SECURITY`,
`CREATE POLICY ...`, `current_setting('app.current_workspace_id', true)::uuid`) that has no
MySQL equivalent and will fail outright.

The current schema is built by a single squashed baseline instead:
`db/migrations/versions/417cf2df2299_mysql_baseline_schema.py`, followed by the 4 rechained
seed-data migrations and one recovery migration -- see that baseline's own docstring for the
full squash rationale, and `apps/api/core/tenancy.py` for how workspace isolation
(previously these files' RLS policies) is enforced now.

## A cautionary note on "pure DDL"

Two of these 21 files are NOT pure schema migrations despite their names, and that mattered:

- `c0ecf2f76c48_add_reports_table.py` also seeded the `report:create` / `report:read`
  permissions inline, in the same `upgrade()` as the `CREATE TABLE reports` + RLS setup.
- `ccf0f32c1190_add_risk_scores_compliance_mappings_.py` also seeded `target:update`
  alongside its `CREATE TABLE risk_scores/compliance_mappings` + `targets.criticality`
  column addition.

When these 21 were first archived, that mixed seed data was silently dropped -- it wasn't
picked up by the MySQL baseline (which only reflects current table shape, not migration-time
data seeds) or by the 4 rechained seed migrations (which only replayed the seed migrations
that were *already* separate files). The gap was only caught by actually running the test
suite against live MySQL and seeing `report:create`/`target:update` permission checks fail
with 403s. It's fixed by
`db/migrations/versions/3c59542f51d4_seed_report_and_target_update_.py`, which
re-seeds exactly what these two files seeded.

The lesson for anyone auditing this directory further: check every file's `upgrade()` for a
`bulk_insert`/`INSERT INTO permissions` call, not just its filename or its `CREATE TABLE`
statements, before concluding a migration was safe to treat as pure DDL.
