"""Dialect-portable column types.

MySQL migration note (Phase 0 — MySQL cutover): the codebase previously used
Postgres-native `sqlalchemy.dialects.postgresql.UUID` and `JSONB` directly in
every model. Those types don't exist on MySQL. Rather than hand-edit each of
the ~25 model files with a MySQL-specific type, every model now imports
`GUID` and `JSONType` from here — one place to reason about "how is a UUID /
a JSON blob actually stored", and one place to change again if we ever need
to (e.g. swap GUID's CHAR(36) storage for a packed BINARY(16) for a
storage/index-size win, without touching a single model).

GUID stores as CHAR(36) (the canonical hyphenated string form, e.g.
"3fa85f64-5717-4562-b3fc-2c963f66afa6") rather than a packed BINARY(16).
CHAR(36) was chosen deliberately for this cutover: it's readable directly in
MySQL Workbench / any SQL client with no conversion function, it's what every
existing `text()` raw-SQL statement in this codebase already assumes when it
does `{"id": str(scan_id)}`, and it avoids a second migration path porting
existing UUID literals. It costs ~20 bytes/row more than BINARY(16) and a
slightly larger index — negligible at this project's scale. Revisit if a
table grows past tens of millions of rows and the index size becomes real.
"""

from __future__ import annotations

import uuid
from datetime import timezone

from sqlalchemy import CHAR, DateTime
from sqlalchemy.dialects import mysql
from sqlalchemy.types import JSON, TypeDecorator


class GUID(TypeDecorator):
    """Platform-independent UUID column.

    Stores as CHAR(36) on every backend (originally also transparently used
    Postgres's native UUID type pre-migration; that branch is gone now that
    Postgres support has been fully removed — see docs/architecture for the
    cutover decision). Python-side value is always `uuid.UUID`.
    """

    impl = CHAR(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return str(value)
        # Accept plain strings too (raw-SQL call sites already pass str(uuid)).
        return str(uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


class UTCDateTime(TypeDecorator):
    """Timezone-aware datetime column, portable to a backend with no real tz-aware storage.

    MySQL migration note (Phase 0 — MySQL cutover): every model previously declared these
    columns as plain `sqlalchemy.DateTime(timezone=True)`. On Postgres that maps to
    TIMESTAMPTZ, which genuinely stores an instant (internally normalized to UTC) and hands
    back tz-aware `datetime` objects. MySQL's DATETIME has no timezone concept at all --
    SQLAlchemy's MySQL dialect silently ignores the `timezone=True` flag (documented
    behavior, confirmed against SQLAlchemy 2.0), storing whatever naive-looking value it's
    given and handing back a naive `datetime` on read. Application code across this codebase
    compares these values against `datetime.now(timezone.utc)` (aware) — e.g.
    `apps/api/modules/auth/service.py`'s refresh-token expiry check -- which raised
    `TypeError: can't compare offset-naive and offset-aware datetimes` the first time it ran
    against live MySQL, since the value read back from `expires_at` had silently become naive.

    This type closes that gap the same way GUID closes the UUID one: bind always converts to
    UTC and strips tzinfo before handing the driver a plain naive value (so it round-trips
    through MySQL's tz-blind DATETIME correctly); result always reattaches
    `tzinfo=timezone.utc` before handing the value back to application code. Every model in
    this codebase treats "naive == UTC" as the storage convention (nothing here ever calls
    `datetime.now()` without `timezone.utc`), so reattaching UTC on read is not a guess.
    A naive datetime passed to process_bind_param is also assumed to already be UTC (rather
    than rejected), since `server_default=func.now()`-populated columns are read back through
    this same path and MySQL's `current_timestamp()` has no offset to convert from.

    PRECISION, found the same way (a live-MySQL test run, not a read-through): plain
    `DateTime` compiles on MySQL to `DATETIME` with 0 fractional digits -- second
    resolution. Postgres's TIMESTAMPTZ defaults to microsecond resolution, and several
    "most recent row" queries in this codebase (e.g.
    apps/api/modules/authorization_scope/service.py's get_current_scope) rely on
    `ORDER BY created_at DESC LIMIT 1` to pick the right row -- which is only reliably
    ordered if two rows created within the same second get distinguishable timestamps.
    Verified empirically: two rows inserted back-to-back in a test landed on the identical
    second and the endpoint returned the wrong one. `with_variant(mysql.DATETIME(fsp=6),
    "mysql")` asks for microsecond precision on MySQL/MariaDB specifically (SQLAlchemy's
    dialect name for both is "mysql" regardless of which server is behind a `mysql+pymysql`
    /`mysql+aiomysql` URL, confirmed against a live MariaDB connection) while leaving the
    plain `DateTime` behavior — and hence TIMESTAMPTZ's own microsecond precision — alone
    on any other dialect. MariaDB automatically upgrades a bare `DEFAULT CURRENT_TIMESTAMP`
    to `DEFAULT current_timestamp(6)` to match a `DATETIME(6)` column (verified directly),
    so `server_default=func.now()` needs no matching change at the call sites.
    """

    impl = DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql")
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001
        if value is None:
            return value
        if value.tzinfo is not None:
            value = value.astimezone(timezone.utc)
        return value.replace(tzinfo=None)

    def process_result_value(self, value, dialect):  # noqa: ANN001
        if value is None:
            return value
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


# MySQL 5.7.8+/8.0 has a native JSON column type; sqlalchemy.types.JSON maps
# to it directly (CHECK (json_valid(...)) storage under the hood). This is a
# straight rename of the import in every model — Postgres's JSONB and generic
# JSON differ in operators, not in the Python-level dict/list contract this
# codebase relies on. Kept as an explicit alias (not "just use sa.JSON
# inline") so every model's import line reads identically to how it reads
# for GUID, and so a future backend-specific tweak (e.g. MySQL's
# JSON_MERGE_PATCH-based partial update) has one place to land.
JSONType = JSON
