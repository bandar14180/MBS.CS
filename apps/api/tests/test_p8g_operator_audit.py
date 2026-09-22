"""MBS.SC PHASE 8 (P8-G) -- durable audit for scanner/VPN operator actions.

THE GAP THIS CLOSES
-------------------
Every Phase 8 control enforced correctly but left NO durable record. Demonstrated during
discovery: a worker revoked through the approved P8-E CLI an hour earlier had vanished --
`platform_audit_events` held 0 rows, and the log line had gone to the operator's `docker
exec` session. Container logs are `json-file` with no rotation and no shipping.

WHAT THESE TESTS PIN
--------------------
  * the migration relaxes exactly ONE column's nullability and nothing else;
  * P8-E writes exactly one audit row, with actor honesty (`unattributed` when omitted) and
    NO secret material;
  * P8-F audits only ACTUAL suspensions, as `system`, and never blocks the sweep;
  * P8-D audits observed TRANSITIONS only -- baseline silent, unchanged silent, one row per
    flip -- with no audit write inside the low-level flag reader;
  * every audit path is BEST EFFORT: a failing audit never breaks the operation.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.audit import scanner_ops
from apps.api.modules.audit.immutability import allow_audit_deletion
from apps.api.modules.audit.platform_models import PlatformAuditEvent
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.ops import revoke_worker as cli


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _sessions():
    return async_sessionmaker(_engine(), expire_on_commit=False)


async def _run(fn):
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                return await fn(s)
    finally:
        await engine.dispose()


def _worker(**kw) -> ScannerWorker:
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"p8g-{uuid.uuid4().hex[:12]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "active"),
        token_hash=kw.get("token_hash", workers_service.hash_worker_token("tok-" + uuid.uuid4().hex)),
        cert_fingerprint=kw.get("cert_fingerprint", "fp-" + uuid.uuid4().hex[:16]),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc)),
    )


async def _events(event: str, needle: str | None = None):
    async def _q(s):
        rows = list(await s.scalars(
            select(PlatformAuditEvent).where(PlatformAuditEvent.event == event)
        ))
        return [r for r in rows if needle is None or (r.detail and needle in r.detail)]
    return await _run(_q)


@pytest.fixture
def disposable_worker():
    w = _worker()

    async def _seed(s):
        s.add(w)
        await s.commit()
    asyncio.run(_run(_seed))
    try:
        yield w
    finally:
        async def _clean(s):
            row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
            if row is not None:
                await s.delete(row)
            # NOTE: this is a raw-SQL DELETE, which the Prompt 34 ORM append-only guard does
            # not (and cannot) intercept -- see immutability.py's documented limits. Left as
            # raw SQL because it deletes by LIKE across rows, not by identity.
            await s.execute(
                text("DELETE FROM platform_audit_events WHERE detail LIKE :p"),
                {"p": f"%{w.worker_id}%"},
            )
            await s.commit()
        asyncio.run(_run(_clean))


# =======================================================================================
# MIGRATION
# =======================================================================================

def test_workspace_id_is_nullable():
    async def _q(s):
        return await s.scalar(text(
            "SELECT IS_NULLABLE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'platform_audit_events' "
            "AND COLUMN_NAME = 'workspace_id'"
        ))
    assert asyncio.run(_run(_q)) == "YES"


def test_the_migration_changed_nothing_else_on_the_table():
    """Only nullability. Type, other columns and their constraints must be untouched."""
    async def _q(s):
        rows = await s.execute(text(
            "SELECT COLUMN_NAME, IS_NULLABLE, COLUMN_TYPE FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'platform_audit_events'"
        ))
        return {r[0]: (r[1], r[2]) for r in rows.fetchall()}
    cols = asyncio.run(_run(_q))
    assert cols["workspace_id"] == ("YES", "char(36)")   # relaxed, type unchanged
    assert cols["id"][0] == "NO"
    assert cols["event"][0] == "NO"
    assert cols["created_at"][0] == "NO"
    assert cols["actor_user_id"][0] == "YES"             # was already nullable
    assert cols["detail"][0] == "YES"
    # `correlation_id` was added later by the Prompt 34 audit-hardening migration
    # (a7b8c9d0e1f2), which is additive and nullable; it is not something P8-G changed.
    assert set(cols) == {
        "id", "workspace_id", "actor_user_id", "event", "detail", "created_at", "correlation_id",
    }
    assert cols["correlation_id"][0] == "YES"


def test_a_workspace_scoped_row_still_writes_and_reads():
    """Existing rows and existing callers (tenant.delete.*) remain valid."""
    ws = uuid.uuid4()

    async def _rt(s):
        from apps.api.modules.audit import service as audit_service
        await audit_service.record_platform_event(s, ws, None, "tenant.delete.requested",
                                                  detail="p8g regression probe")
        await s.commit()
        row = await s.scalar(
            select(PlatformAuditEvent).where(PlatformAuditEvent.workspace_id == ws)
        )
        got = (row.workspace_id, row.event)
        with allow_audit_deletion():  # Prompt 34: append-only guard; teardown is deliberate.
            await s.delete(row)
            await s.commit()
        return got
    assert asyncio.run(_run(_rt)) == (ws, "tenant.delete.requested")


def test_a_platform_scoped_row_can_now_be_written():
    """THE point of the migration: workspace_id NULL for a platform-wide event."""
    async def _rt(s):
        ok = await scanner_ops.record_emergency_transition(s, previous=False, current=True)
        await s.commit()
        row = await s.scalar(
            select(PlatformAuditEvent)
            .where(PlatformAuditEvent.event == scanner_ops.EVENT_EMERGENCY_TRANSITION)
            .order_by(PlatformAuditEvent.created_at.desc())
        )
        got = (ok, row.workspace_id, row.detail)
        with allow_audit_deletion():  # Prompt 34: append-only guard; teardown is deliberate.
            await s.delete(row)
            await s.commit()
        return got
    ok, ws_id, detail = asyncio.run(_rt if False else _run(_rt))
    assert ok is True
    assert ws_id is None
    assert "source=observed_runtime_transition" in detail


# =======================================================================================
# P8-E -- worker revocation
# =======================================================================================

def test_revocation_writes_exactly_one_audit_event(disposable_worker):
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "suspected compromise",
              "--actor", "oncall-alice"])
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    assert len(rows) == 1
    d = rows[0].detail
    assert f"worker_id={disposable_worker.worker_id}" in d
    assert "reason=suspected compromise" in d
    assert "actor=oncall-alice" in d
    assert "outcome=revoked" in d


def test_an_omitted_actor_is_recorded_as_unattributed(disposable_worker):
    """Never invent an identity; record the absence as a fact."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "no actor given"])
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    assert len(rows) == 1
    assert f"actor={scanner_ops.ACTOR_UNATTRIBUTED}" in rows[0].detail


def test_the_actor_is_never_presented_as_authenticated(disposable_worker):
    """A CLI has no authenticated principal, so the record says so and `actor_user_id`
    -- the column for a VERIFIED user -- stays NULL."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "r", "--actor", "bob"])
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    assert "actor_authenticated=false" in rows[0].detail
    assert rows[0].actor_user_id is None


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_actor_normalises_to_unattributed(blank):
    assert scanner_ops.normalise_actor(blank) == scanner_ops.ACTOR_UNATTRIBUTED
    assert scanner_ops.normalise_actor(None) == scanner_ops.ACTOR_UNATTRIBUTED


def test_no_secret_material_reaches_the_audit_detail(disposable_worker):
    """A durable audit trail is the worst possible place to accumulate credentials."""
    token_hash = disposable_worker.token_hash
    fingerprint = disposable_worker.cert_fingerprint
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "routine check"])
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    d = rows[0].detail
    # The VALUES must be absent -- that is what leaking would mean.
    assert token_hash not in d
    assert fingerprint not in d
    # ...and no credential-bearing FIELD is emitted. (The operator's free-text reason is
    # echoed verbatim by design, so the field names are what this can assert on.)
    for field in ("token_hash=", "cert_fingerprint=", "token=", "secret=", "credential="):
        assert field not in d.lower()


def test_a_public_worker_revocation_is_platform_scoped(disposable_worker):
    """A shared public worker has workspace_id NULL, so its audit row does too."""
    assert disposable_worker.workspace_id is None
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "public worker"])
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    assert rows[0].workspace_id is None


def test_a_private_worker_revocation_carries_its_workspace():
    # A REAL workspace: scanner_workers.workspace_id carries an FK, so a random UUID is
    # rejected by the database rather than by anything under test.
    async def _pick(s):
        from apps.api.modules.workspaces.models import Workspace
        return await s.scalar(select(Workspace.id).limit(1))
    ws = asyncio.run(_run(_pick))
    if ws is None:
        pytest.skip("no workspace available in this database")
    w = _worker(pool_id="private-x", workspace_id=ws, site_id=None)

    async def _seed(s):
        s.add(w)
        await s.commit()
    asyncio.run(_run(_seed))
    try:
        cli.main(["--worker-id", w.worker_id, "--reason", "private worker"])
        rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, w.worker_id))
        assert len(rows) == 1
        assert rows[0].workspace_id == ws
    finally:
        async def _clean(s):
            row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
            if row:
                await s.delete(row)
            await s.execute(text("DELETE FROM platform_audit_events WHERE detail LIKE :p"),
                            {"p": f"%{w.worker_id}%"})
            await s.commit()
        asyncio.run(_run(_clean))


def test_an_audit_failure_does_not_undo_or_block_the_revocation(disposable_worker, monkeypatch):
    """BEST EFFORT: a compromised worker must still be cut off when auditing is broken."""
    async def _boom(*a, **kw):
        raise RuntimeError("audit table unavailable")

    monkeypatch.setattr(scanner_ops, "record_worker_revoked", _boom)
    rc = cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "audit down"])
    assert rc == 0

    async def _q(s):
        return await s.scalar(
            select(ScannerWorker).where(ScannerWorker.worker_id == disposable_worker.worker_id)
        )
    got = asyncio.run(_run(_q))
    assert got.status == "revoked"          # commit semantics intact
    assert got.token_hash is None


def test_the_audit_row_survives_deletion_of_the_worker(disposable_worker):
    """Non-cascading by design -- the record must outlive what it describes."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "survival check"])

    async def _del(s):
        row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == disposable_worker.id))
        await s.delete(row)
        await s.commit()
    asyncio.run(_run(_del))
    rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REVOKED, disposable_worker.worker_id))
    assert len(rows) == 1


# =======================================================================================
# P8-F -- stale reaper
# =======================================================================================

def _stale_worker(**kw):
    return _worker(last_seen_at=datetime.now(timezone.utc) - timedelta(seconds=99999), **kw)


def test_a_suspension_writes_one_audit_event_as_system():
    w = _stale_worker()

    async def _go(s):
        s.add(w)
        await s.commit()
        n = await workers_service.reap_stale_workers(s, 600)
        return n
    n = asyncio.run(_run(_go))
    try:
        assert n >= 1
        rows = asyncio.run(_events(scanner_ops.EVENT_WORKER_REAPED_STALE, w.worker_id))
        assert len(rows) == 1
        d = rows[0].detail
        assert f"actor={scanner_ops.ACTOR_SYSTEM}" in d
        assert "previous_status=active" in d and "new_status=suspended" in d
        assert "no heartbeat for 600s" in d
        # System-generated: never 'unattributed', which would imply a person we failed to name.
        assert scanner_ops.ACTOR_UNATTRIBUTED not in d
    finally:
        async def _clean(s):
            row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
            if row:
                await s.delete(row)
            await s.execute(text("DELETE FROM platform_audit_events WHERE detail LIKE :p"),
                            {"p": f"%{w.worker_id}%"})
            await s.commit()
        asyncio.run(_run(_clean))


def test_a_zero_suspension_sweep_writes_no_audit_row():
    """An audit trail of non-events is noise that hides the real ones."""
    async def _count(s):
        return await s.scalar(text(
            "SELECT COUNT(*) FROM platform_audit_events WHERE event = :e"
        ), {"e": scanner_ops.EVENT_WORKER_REAPED_STALE})

    before = asyncio.run(_run(_count))

    async def _sweep(s):
        # Threshold far in the future -> nothing is stale -> nothing suspended.
        return await workers_service.reap_stale_workers(s, 10_000_000)
    assert asyncio.run(_run(_sweep)) == 0
    assert asyncio.run(_run(_count)) == before


def test_an_audit_failure_does_not_block_the_reaper(monkeypatch):
    w = _stale_worker()

    async def _boom(*a, **kw):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(scanner_ops, "record_worker_reaped_stale", _boom)

    async def _go(s):
        s.add(w)
        await s.commit()
        n = await workers_service.reap_stale_workers(s, 600)
        row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
        await s.refresh(row)
        return n, row.status
    n, status = asyncio.run(_run(_go))
    try:
        assert n >= 1
        assert status == "suspended"     # the suspension still happened
    finally:
        async def _clean(s):
            row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
            if row:
                await s.delete(row)
            await s.commit()
        asyncio.run(_run(_clean))


def test_a_revoked_worker_is_still_protected_from_the_reaper():
    """P8-F semantics unchanged by P8-G."""
    w = _stale_worker(status="revoked")
    w.revoked_at = datetime.now(timezone.utc)

    async def _go(s):
        s.add(w)
        await s.commit()
        await workers_service.reap_stale_workers(s, 0)
        row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
        await s.refresh(row)
        return row.status
    try:
        assert asyncio.run(_run(_go)) == "revoked"
    finally:
        async def _clean(s):
            row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
            if row:
                await s.delete(row)
            await s.commit()
        asyncio.run(_run(_clean))


# =======================================================================================
# P8-D -- observed emergency transitions
# =======================================================================================

@pytest.fixture
def clean_emergency_state():
    import apps.api.scanner_manager.app as mgr

    mgr._EMERGENCY_STATE.clear()
    yield mgr
    mgr._EMERGENCY_STATE.clear()

    async def _clean(s):
        await s.execute(text("DELETE FROM platform_audit_events WHERE event = :e"),
                        {"e": scanner_ops.EVENT_EMERGENCY_TRANSITION})
        await s.commit()
    asyncio.run(_run(_clean))


def _emergency_rows():
    return asyncio.run(_events(scanner_ops.EVENT_EMERGENCY_TRANSITION))


def test_the_first_observation_is_a_silent_baseline(clean_emergency_state):
    """Process start is not a transition -- auditing it would log a flip that never happened."""
    mgr = clean_emergency_state
    asyncio.run(_run(lambda s: mgr._audit_emergency_transition(s, False)))
    assert _emergency_rows() == []
    assert mgr._EMERGENCY_STATE["effective"] is False


def test_an_unchanged_observation_writes_nothing(clean_emergency_state):
    """The 5s TTL means this is polled constantly; only changes are events."""
    mgr = clean_emergency_state

    async def _poll(s):
        for _ in range(5):
            await mgr._audit_emergency_transition(s, False)
    asyncio.run(_run(_poll))
    assert _emergency_rows() == []


def test_false_to_true_writes_exactly_one_event(clean_emergency_state):
    mgr = clean_emergency_state

    async def _go(s):
        await mgr._audit_emergency_transition(s, False)   # baseline
        await mgr._audit_emergency_transition(s, True)    # transition
        await mgr._audit_emergency_transition(s, True)    # unchanged
        await mgr._audit_emergency_transition(s, True)    # unchanged
    asyncio.run(_run(_go))
    rows = _emergency_rows()
    assert len(rows) == 1
    assert "previous=false" in rows[0].detail and "current=true" in rows[0].detail


def test_true_to_false_writes_exactly_one_event(clean_emergency_state):
    mgr = clean_emergency_state

    async def _go(s):
        await mgr._audit_emergency_transition(s, True)    # baseline
        await mgr._audit_emergency_transition(s, False)   # transition
        await mgr._audit_emergency_transition(s, False)   # unchanged
    asyncio.run(_run(_go))
    rows = _emergency_rows()
    assert len(rows) == 1
    assert "previous=true" in rows[0].detail and "current=false" in rows[0].detail


def test_a_full_cycle_writes_exactly_two_events(clean_emergency_state):
    mgr = clean_emergency_state

    async def _go(s):
        for state in (False, False, True, True, False, False):
            await mgr._audit_emergency_transition(s, state)
    asyncio.run(_run(_go))
    assert len(_emergency_rows()) == 2


def test_the_transition_event_is_system_attributed_and_platform_scoped(clean_emergency_state):
    mgr = clean_emergency_state

    async def _go(s):
        await mgr._audit_emergency_transition(s, False)
        await mgr._audit_emergency_transition(s, True)
    asyncio.run(_run(_go))
    row = _emergency_rows()[0]
    assert row.workspace_id is None                       # platform-wide
    assert row.actor_user_id is None
    d = row.detail
    assert f"actor={scanner_ops.ACTOR_SYSTEM}" in d
    assert "source=observed_runtime_transition" in d      # observed, not attributed
    assert "actor_authenticated=false" in d
    assert "subject=private_scanning_emergency_state" in d


def test_the_transition_detail_contains_no_path_or_environment_value(clean_emergency_state):
    mgr = clean_emergency_state

    async def _go(s):
        await mgr._audit_emergency_transition(s, False)
        await mgr._audit_emergency_transition(s, True)
    asyncio.run(_run(_go))
    d = _emergency_rows()[0].detail
    for forbidden in ("/run/mbs", "EMERGENCY_DISABLE_PRIVATE_SCANNING", "SCAN_ALLOW", "token"):
        assert forbidden not in d


def test_an_audit_failure_does_not_break_emergency_enforcement(clean_emergency_state, monkeypatch):
    """Enforcement is decided before the audit runs; a broken audit must not re-enable
    private scanning."""
    mgr = clean_emergency_state

    async def _boom(*a, **kw):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(scanner_ops, "record_emergency_transition", _boom)

    async def _go(s):
        await mgr._audit_emergency_transition(s, False)
        await mgr._audit_emergency_transition(s, True)    # must not raise
    asyncio.run(_run(_go))
    # State still advanced, so the failure is not retried forever on every request.
    assert mgr._EMERGENCY_STATE["effective"] is True


def test_no_audit_write_occurs_inside_the_low_level_flag_reader():
    """runtime_flags is the fail-closed hot-path filesystem read: it must hold no DB session
    and perform no audit write."""
    import inspect

    from apps.api.core import runtime_flags

    src = inspect.getsource(runtime_flags)
    for forbidden in ("record_platform_event", "scanner_ops", "AsyncSession", "audit",
                      "commit(", "PlatformAuditEvent"):
        assert forbidden not in src, f"runtime_flags must stay audit-free: {forbidden}"


def test_p8d_enforcement_semantics_are_unchanged():
    from apps.api.core import runtime_flags

    assert runtime_flags.FLAG_TTL_SECONDS == 5.0
    assert runtime_flags.EMERGENCY_DISABLE_SENTINEL == "EMERGENCY_DISABLE_PRIVATE_SCANNING"


# =======================================================================================
# Naming / shared helper invariants
# =======================================================================================

def test_event_names_follow_the_existing_convention_and_fit_the_column():
    for name in (scanner_ops.EVENT_WORKER_REVOKED,
                 scanner_ops.EVENT_WORKER_REAPED_STALE,
                 scanner_ops.EVENT_EMERGENCY_TRANSITION):
        assert "." in name                 # noun.verb, like tenant.delete.*
        assert len(name) <= 64             # platform_audit_events.event is String(64)
        assert name == name.lower()


def test_the_audit_helper_never_raises():
    """Every public helper is best-effort; a broken audit path returns False, not an error."""
    class _BrokenSession:
        def add(self, *a, **kw):
            raise RuntimeError("db down")

        async def flush(self):
            raise RuntimeError("db down")

    async def _go():
        return (
            await scanner_ops.record_worker_revoked(
                _BrokenSession(), worker_id="w", reason="r", actor=None,
                workspace_id=None, site_id=None),
            await scanner_ops.record_worker_reaped_stale(
                _BrokenSession(), worker_id="w", stale_after_seconds=600,
                workspace_id=None, site_id=None),
            await scanner_ops.record_emergency_transition(
                _BrokenSession(), previous=False, current=True),
        )
    assert asyncio.run(_go()) == (False, False, False)


# =======================================================================================
# REGRESSION
# =======================================================================================

def test_phase7_per_job_gate_is_unchanged():
    from apps.api.scanner_engine import wireguard
    from apps.api.scanner_worker.lease_loop import LeaseError, preflight_private_job

    down = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    job = {"network_zone": "private", "site_id": "s", "authorized_cidrs": ["10.90.0.0/24"]}
    with pytest.raises(LeaseError):
        preflight_private_job(job, probe=down)
    preflight_private_job({"network_zone": "public"}, probe=None)


def test_p8a_b_c_are_unchanged():
    from apps.api.scanner_manager.app import _worker_metric_lines
    from apps.api.scanner_worker.lease_loop import LeaseLoop

    assert hasattr(LeaseLoop, "observe_tunnel_health")
    assert hasattr(LeaseLoop, "report_health")
    now = datetime(2026, 9, 12, 0, 0, 0, tzinfo=timezone.utc)

    class _R:
        pool_id = "private-lab-a"
        site_id = "s1"
        health_state = "healthy"
        last_handshake_age_s = 40
        last_seen_at = now - timedelta(seconds=5)

    assert 'mbs_tunnel_up{pool_id="private-lab-a"} 1' in "\n".join(
        _worker_metric_lines([_R()], now=now)
    )


def test_the_runbook_documents_the_completed_phase8_behaviour():
    from pathlib import Path

    doc = Path(__file__).resolve().parents[3] / "docs" / "runbooks" / "private-scanning.md"
    if not doc.is_file():
        pytest.skip("runbook not present in this environment")
    text_ = doc.read_text(encoding="utf-8")
    for needed in ("--actor", "unattributed", "observed", "mbs_tunnel_up",
                   "health_state", "reaper"):
        assert needed in text_, f"runbook missing: {needed}"
