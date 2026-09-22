"""Widen assets.value to VARCHAR(2048), keyed by a generated SHA-256 hash

WHY
---
Scan 615d0e0b-32a6-4192-95c9-c974c0df62b0 (brightvision-og.com) failed because katana
legitimately discovered a ~700-character URL -- a `https://wa.me/...` share link whose
`?text=` parameter carries a full URL-encoded marketing message -- and `assets.value` was
VARCHAR(512). MySQL raised

    (1406, "Data too long for column 'value' at row 1")

which surfaced as HTTP 500 from /v1/tool-results, rolled back the ToolRun status update in
the same transaction (leaving katana `running` forever), and aborted the scan pipeline
before ffuf/arjun/nuclei/nuclei-dast ever started.

Long URLs are NOT malformed input. Query strings, share links, tracking parameters and
signed URLs routinely exceed 512 characters, so the column -- not the crawler -- was wrong.

WHY THE VALUE CANNOT SIMPLY BE WIDENED IN PLACE
-----------------------------------------------
`value` is the third column of the unique key `uq_assets_target_type_value`
(target_id, asset_type, value), which is what makes asset discovery idempotent across
re-scans. InnoDB caps an index key at 3072 bytes, and this table is utf8mb4 (4 bytes per
character), so the key budget is:

    3072 - (36 chars target_id * 4) - (32 chars asset_type * 4) = 2800 bytes = 700 chars

A plain `ALTER TABLE assets MODIFY value VARCHAR(2048)` is therefore REJECTED outright:

    ERROR 1071 (42000): Specified key was too long; max key length is 3072 bytes

(verified directly against this deployment's MySQL 8.0.46, utf8mb4, DYNAMIC row format,
16K page). Widening to 700 characters would have fit, but it only moves the same cliff a
little further out -- the incident URL was already ~700 characters.

THE FIX: HASH THE KEY, STORE THE VALUE
--------------------------------------
`value` becomes VARCHAR(2048) and is removed from the unique key. Uniqueness moves to a
STORED GENERATED column:

    value_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(value, 256))) STORED

and the key becomes (target_id, asset_type, value_hash) -- 36*4 + 32*4 + 32 = 304 bytes,
comfortably inside the limit and independent of how long `value` grows in future.

Semantics are PRESERVED exactly, which is the point:
  * the uniqueness grain is still one row per (target, type, value);
  * the hash is derived by MySQL from `value` itself, so it cannot drift from the data and
    needs no application code to maintain;
  * `ON DUPLICATE KEY UPDATE` continues to work unchanged -- verified against a scratch
    table that two upserts of the same 700-character value yield exactly one row.

SHA-256 collisions are not a practical concern for asset dedup; a collision would merge two
distinct URLs for one target, which is vastly less likely than the hardware faults this
system already tolerates.

WHY BINARY(32) AND NOT CHAR(64)
-------------------------------
UNHEX() halves the stored/indexed width (32 bytes vs 64 characters) and BINARY comparison is
byte-exact, so it cannot be affected by the table's utf8mb4_unicode_ci collation -- which is
case-INSENSITIVE and would otherwise make two hex digests differing only in case compare
equal. Byte semantics are what a digest key needs.

WHY STORED AND NOT VIRTUAL
--------------------------
MySQL 8.0 supports indexes on virtual columns, but a STORED column keeps the index a plain
secondary index over materialised bytes, which is what the existing upsert path expects and
avoids re-evaluating SHA2() on every row touched during an index scan.

DATA SAFETY
-----------
Widening 512 -> 2048 is non-destructive: every existing value still fits and reads back
identically. The generated column is computed by MySQL for all existing rows during the
ALTER, so no backfill statement is needed and no row is rewritten by application code.
Because the OLD unique key already guaranteed (target_id, asset_type, value) uniqueness, and
the hash is a function of value, the NEW key cannot collide on data that was previously
valid -- the ALTER cannot fail on duplicates.

DOWNGRADE
---------
Reversible, with one honest caveat that is asserted rather than ignored: values longer than
512 characters cannot be narrowed back without destroying data. The downgrade therefore
REFUSES to run while any such row exists, rather than letting MySQL silently truncate them
(or failing halfway with STRICT mode off). Delete or shorten those rows first if a genuine
rollback is ever required.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-09-12 02:10:00.000000

"""
import sqlalchemy as sa
from alembic import op

# Annotated form (`revision: str = ...`) deliberately: the schema-version gate
# (test_schema_version_gate) derives the application's head revision by scanning these files
# for exactly that spelling, so the HEAD migration must use it or the gate cannot find it.
revision: str = "f7a8b9c0d1e2"
down_revision: str = "e6f7a8b9c0d1"
branch_labels = None
depends_on = None

# The generated-column expression, defined once so upgrade() and the model stay in step.
_HASH_EXPR = "UNHEX(SHA2(`value`, 256))"


def upgrade() -> None:
    # ORDER MATTERS. The unique key must be dropped BEFORE `value` is widened: while the key
    # still contains `value`, the widening is exactly the ALTER that MySQL rejects with
    # "Specified key was too long".
    op.drop_constraint("uq_assets_target_type_value", "assets", type_="unique")

    # existing_* are supplied because MySQL's MODIFY COLUMN rewrites the whole column
    # definition -- omitting them would drop NOT NULL or the collation.
    op.alter_column(
        "assets",
        "value",
        existing_type=sa.String(512),
        type_=sa.String(2048),
        existing_nullable=False,
        nullable=False,
    )

    # Added AFTER the widening so the generated expression is defined over the final type.
    op.execute(
        "ALTER TABLE assets "
        f"ADD COLUMN value_hash BINARY(32) GENERATED ALWAYS AS ({_HASH_EXPR}) STORED NOT NULL"
    )

    # Same name as before, so nothing that references the constraint by name has to change;
    # the grain it enforces is identical, only the third column is now the digest.
    op.create_unique_constraint(
        "uq_assets_target_type_value", "assets", ["target_id", "asset_type", "value_hash"]
    )


def downgrade() -> None:
    # FAIL CLOSED on data that cannot survive the narrowing. Checked first, before anything
    # is dropped, so a refused downgrade leaves the schema exactly as it was.
    too_long = op.get_bind().execute(
        sa.text("SELECT COUNT(*) FROM assets WHERE CHAR_LENGTH(`value`) > 512")
    ).scalar()
    if too_long:
        raise RuntimeError(
            f"Refusing to downgrade: {too_long} asset value(s) exceed 512 characters and "
            "would be truncated or rejected by the narrower column. Shorten or delete those "
            "rows first if this rollback is genuinely intended."
        )

    op.drop_constraint("uq_assets_target_type_value", "assets", type_="unique")
    op.execute("ALTER TABLE assets DROP COLUMN value_hash")
    op.alter_column(
        "assets",
        "value",
        existing_type=sa.String(2048),
        type_=sa.String(512),
        existing_nullable=False,
        nullable=False,
    )
    op.create_unique_constraint(
        "uq_assets_target_type_value", "assets", ["target_id", "asset_type", "value"]
    )
