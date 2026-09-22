"""MBS.SC PHASE 8 (P8-F) -- PROVENANCE for worker reactivation.

THE GAP THESE CLOSE
-------------------
A forensic audit of the 2026-09-17 production reactivation could not attribute it. The row
recorded `actor=blocker-1-remediation` -- a free-text `--actor` value matching nothing in the
repository -- and every source that could have identified the invoker was unavailable: shell
history did not cover the window, Docker exec events were not retained, and MySQL
`general_log` is off. The audit row proved WHAT happened and WHEN, but not WHO or FROM WHERE.

Two distinct defects were found, and these tests pin both fixes:

  1. NO MACHINE-VERIFIABLE PROVENANCE. `actor` is what the operator CLAIMS. Nothing recorded
     what the process demonstrably WAS, so "run inside a control-plane container" could not
     be told apart from "run on a developer laptop".

  2. ONLY SUCCESSES WERE AUDITED. Both CLI failure paths returned before the audit call, so a
     refused attempt -- including one against a `revoked` worker, the single event an auditor
     most wants -- left no trace at all. A trail of successes cannot distinguish "nobody
     tried" from "somebody tried and the guard held".

WHAT IS DELIBERATELY *NOT* CLAIMED
----------------------------------
`os_user` / `source_host` / `source_pid` are OBSERVED, not AUTHENTICATED. A caller able to
run the CLI can influence them. They make an honest action self-documenting and raise the
cost of an anonymous one; they do not make the actor trustworthy, which is why
`actor_authenticated=false` is unchanged and asserted below.

Historical rows are NOT touched and no provenance is invented for them.
"""
import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.audit import scanner_ops
from apps.api.modules.audit.platform_models import PlatformAuditEvent
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker

EVENT_OK = scanner_ops.EVENT_WORKER_REACTIVATED
EVENT_FAIL = scanner_ops.EVENT_WORKER_REACTIVATION_FAILED

# Anything that must NEVER reach a durable audit row (rule 2 of scanner_ops).
SECRET_MARKERS = ("token", "secret", "password", "authorization", "bearer",
                  "fingerprint", "cert", "private", "credential", "api_key")


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


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
        worker_id=kw.get("worker_id", f"prov-{uuid.uuid4().hex[:12]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "suspended"),
        token_hash=kw.get(
            "token_hash", workers_service.hash_worker_token("tok-" + uuid.uuid4().hex)),
        cert_fingerprint=kw.get("cert_fingerprint", "fp-" + uuid.uuid4().hex[:16]),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc)),
        revoked_at=kw.get("revoked_at"),
    )


async def _events(event: str, needle: str) -> list:
    async def _q(s):
        rows = list(await s.scalars(
            select(PlatformAuditEvent).where(PlatformAuditEvent.event == event)))
        return [r for r in rows if r.detail and needle in r.detail]
    return await _run(_q)


def _kv(detail: str) -> dict:
    """Parse the `k=v` audit detail. `reason` is free text with spaces, so it is taken as
    the remainder -- matching how `_format_detail` builds the line."""
    out, rest = {}, detail
    if " reason=" in rest:
        rest, reason = rest.split(" reason=", 1)
        out["reason"] = reason
    for tok in rest.split(" "):
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k] = v
    return out


@pytest.fixture
def disposable():
    """A worker row plus every audit row naming it, removed afterwards."""
    made: list[ScannerWorker] = []

    def _mk(**kw) -> ScannerWorker:
        w = _worker(**kw)

        async def _seed(s):
            s.add(w)
            await s.commit()
        asyncio.run(_run(_seed))
        made.append(w)
        return w

    try:
        yield _mk
    finally:
        async def _clean(s):
            for w in made:
                row = await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
                if row is not None:
                    await s.delete(row)
                await s.execute(
                    text("DELETE FROM platform_audit_events WHERE detail LIKE :p"),
                    {"p": f"%{w.worker_id}%"},
                )
            await s.commit()
        asyncio.run(_run(_clean))


# =========================================================================================
# TEST 1 -- a successful reactivation records exactly ONE provenance event
# =========================================================================================

def test_a_successful_reactivation_records_exactly_one_event(disposable):
    w = disposable(status="suspended")

    async def _go(s):
        await workers_service.reactivate_worker(s, w.worker_id, reason="unit: recovery")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="unit: recovery", actor="ops-jane",
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
    asyncio.run(_run(_go))

    rows = asyncio.run(_events(EVENT_OK, w.worker_id))
    assert len(rows) == 1, "exactly one row per successful reactivation"
    d = _kv(rows[0].detail)
    assert d["result"] == "success"
    assert d["previous_status"] == "suspended"
    assert d["new_status"] == "active"
    assert d["outcome"] == "active"


# =========================================================================================
# TEST 2 -- a FAILED attempt records a failed-attempt event
# =========================================================================================

def test_a_refused_reactivation_records_a_failure_event(disposable):
    """The half that was missing entirely: an attempt that changed nothing is still recorded."""
    w = disposable(status="revoked", revoked_at=datetime.now(timezone.utc))

    async def _go(s):
        with pytest.raises(workers_service.WorkerNotReactivatable) as ei:
            await workers_service.reactivate_worker(s, w.worker_id, reason="unit: refused")
        await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=w.worker_id, reason="unit: refused", actor="ops-jane",
            failure=ei.value.reason, observed_status="revoked")
        await s.commit()
    asyncio.run(_run(_go))

    rows = asyncio.run(_events(EVENT_FAIL, w.worker_id))
    assert len(rows) == 1
    d = _kv(rows[0].detail)
    assert d["result"] == "failure"
    assert d["outcome"] == "refused"
    assert d["observed_status"] == "revoked"
    assert d["failure"] == workers_service.REASON_NOT_REACTIVATABLE
    # A refusal changed nothing, so it must NOT claim a resulting state.
    assert "new_status" not in d

    # ...and the worker really was not resurrected.
    async def _check(s):
        return await s.scalar(select(ScannerWorker).where(ScannerWorker.id == w.id))
    assert asyncio.run(_run(_check)).status == "revoked"


def test_a_refused_attempt_writes_no_success_event(disposable):
    """A failure must never appear in the success stream -- otherwise an auditor counting
    readmissions would over-count them."""
    w = disposable(status="active")

    async def _go(s):
        with pytest.raises(workers_service.WorkerNotReactivatable) as ei:
            await workers_service.reactivate_worker(s, w.worker_id, reason="unit: wrong state")
        await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=w.worker_id, reason="unit: wrong state", actor=None,
            failure=ei.value.reason, observed_status="active")
        await s.commit()
    asyncio.run(_run(_go))

    assert asyncio.run(_events(EVENT_OK, w.worker_id)) == []
    assert len(asyncio.run(_events(EVENT_FAIL, w.worker_id))) == 1


# =========================================================================================
# TEST 3 / 4 -- actor attribution: claimed vs observed, and never guessed
# =========================================================================================

def test_the_operator_supplied_actor_is_recorded_as_unauthenticated(disposable):
    w = disposable(status="suspended")

    async def _go(s):
        await workers_service.reactivate_worker(s, w.worker_id, reason="r")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="oncall-alice",
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
    asyncio.run(_run(_go))

    d = _kv(asyncio.run(_events(EVENT_OK, w.worker_id))[0].detail)
    assert d["actor"] == "oncall-alice"
    # The claim is recorded AS a claim. This is the honesty rule and must not regress.
    assert d["actor_authenticated"] == "false"
    assert d["actor_type"] == scanner_ops.ACTOR_TYPE_OPERATOR_CLI


def test_an_omitted_actor_is_unattributed_never_invented(disposable):
    """`unknown who` is a fact worth recording; a fabricated identity would be worse."""
    w = disposable(status="suspended")

    async def _go(s):
        await workers_service.reactivate_worker(s, w.worker_id, reason="r")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor=None,
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
    asyncio.run(_run(_go))

    d = _kv(asyncio.run(_events(EVENT_OK, w.worker_id))[0].detail)
    assert d["actor"] == scanner_ops.ACTOR_UNATTRIBUTED


def test_machine_verifiable_source_identity_is_recorded(disposable):
    """THE CORE FIX. `actor` is claimed; these three are observed, and they are what would
    have separated 'inside a control-plane container' from 'on the developer host'."""
    w = disposable(status="suspended")

    async def _go(s):
        await workers_service.reactivate_worker(s, w.worker_id, reason="r")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="claimed-name",
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
    asyncio.run(_run(_go))

    d = _kv(asyncio.run(_events(EVENT_OK, w.worker_id))[0].detail)
    for field in ("os_user", "source_host", "source_pid"):
        assert field in d, f"{field} must be recorded"
        assert d[field], f"{field} must not be empty"
    assert d["source_pid"].isdigit()
    # Observed identity is independent of the claimed one.
    assert d["actor"] == "claimed-name"


def test_the_system_actor_type_is_distinct_from_the_operator_one():
    """A background/system action must never be attributable to a human. The reaper's rows
    already use `actor=system`; the two type constants must stay distinct so a future caller
    cannot blur them."""
    assert scanner_ops.ACTOR_TYPE_SYSTEM != scanner_ops.ACTOR_TYPE_OPERATOR_CLI
    assert scanner_ops.ACTOR_SYSTEM == "system"


def test_the_reaper_still_records_itself_as_system(disposable):
    """P8-F suspensions are system-generated and must stay that way -- never `unattributed`,
    which would imply a person we failed to identify."""
    w = disposable(status="active")

    async def _go(s):
        await scanner_ops.record_worker_reaped_stale(
            s, worker_id=w.worker_id, stale_after_seconds=600,
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
    asyncio.run(_run(_go))

    d = _kv(asyncio.run(_events(scanner_ops.EVENT_WORKER_REAPED_STALE, w.worker_id))[0].detail)
    assert d["actor"] == scanner_ops.ACTOR_SYSTEM
    assert d["previous_status"] == "active"
    assert d["new_status"] == "suspended"


# =========================================================================================
# TEST 5 / 6 -- correlation and identifier association
# =========================================================================================

def test_unavailable_provenance_is_explicit_never_fabricated(monkeypatch, disposable):
    """When the platform cannot determine a value it must say so. An invented hostname is
    worse than an honest `unknown`."""
    import getpass
    import socket

    monkeypatch.setattr(getpass, "getuser", lambda: (_ for _ in ()).throw(OSError("no pwd")))
    monkeypatch.setattr(socket, "gethostname", lambda: (_ for _ in ()).throw(OSError("no dns")))

    os_user, host, pid = scanner_ops._source_identity()
    assert os_user == scanner_ops.PROVENANCE_UNKNOWN
    assert host == scanner_ops.PROVENANCE_UNKNOWN
    assert pid.isdigit()  # pid is always obtainable


def test_worker_and_site_identifiers_are_associated(disposable):
    """A private worker's site must appear, so an auditor can scope the event to a tenant."""
    site = uuid.uuid4()
    ws = uuid.uuid4()
    w = disposable(status="suspended", worker_id=f"prov-priv-{uuid.uuid4().hex[:8]}")

    async def _go(s):
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="a",
            workspace_id=ws, site_id=site)
        await s.commit()
    asyncio.run(_run(_go))

    row = asyncio.run(_events(EVENT_OK, w.worker_id))[0]
    d = _kv(row.detail)
    assert d["worker_id"] == w.worker_id
    assert d["site_id"] == str(site)
    assert row.workspace_id == ws  # tenant scoping via the column, as the schema intends


def test_a_public_worker_records_no_site_and_stays_platform_scoped(disposable):
    """A shared public worker has no site and no workspace; the row must not invent either."""
    w = disposable(status="suspended")

    async def _go(s):
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="a",
            workspace_id=None, site_id=None)
        await s.commit()
    asyncio.run(_run(_go))

    row = asyncio.run(_events(EVENT_OK, w.worker_id))[0]
    assert "site_id=" not in row.detail
    assert row.workspace_id is None


# =========================================================================================
# TEST 7 -- unauthorized / unknown worker still rejected, and recorded
# =========================================================================================

def test_an_unknown_worker_is_refused_and_the_attempt_is_recorded():
    """The probing case: an attempt against an id that does not exist changes nothing but
    must still be visible."""
    ghost = f"prov-ghost-{uuid.uuid4().hex[:10]}"

    async def _go(s):
        with pytest.raises(workers_service.WorkerNotAuthorized) as ei:
            await workers_service.reactivate_worker(s, ghost, reason="unit: ghost")
        await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=ghost, reason="unit: ghost", actor="prober",
            failure=ei.value.reason, observed_status=None)
        await s.commit()
    asyncio.run(_run(_go))

    try:
        rows = asyncio.run(_events(EVENT_FAIL, ghost))
        assert len(rows) == 1
        d = _kv(rows[0].detail)
        assert d["failure"] == workers_service.REASON_UNKNOWN_WORKER
        # Unknown row -> no status could be observed; recorded explicitly, not guessed.
        assert d["observed_status"] == scanner_ops.PROVENANCE_UNKNOWN
    finally:
        async def _clean(s):
            await s.execute(
                text("DELETE FROM platform_audit_events WHERE detail LIKE :p"),
                {"p": f"%{ghost}%"})
            await s.commit()
        asyncio.run(_run(_clean))


# =========================================================================================
# TEST 10 -- no secrets in provenance records
# =========================================================================================

def test_audit_rows_contain_no_secret_material(disposable):
    """Rule 2 of scanner_ops. The worker below carries a token hash and a cert fingerprint;
    neither may reach the audit row, and the new provenance fields must not leak either."""
    w = disposable(status="suspended")

    async def _go(s):
        await workers_service.reactivate_worker(s, w.worker_id, reason="r")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="a",
            workspace_id=w.workspace_id, site_id=w.site_id)
        await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=w.worker_id, reason="r", actor="a",
            failure="X", observed_status="active")
        await s.commit()
    asyncio.run(_run(_go))

    details = [r.detail for r in asyncio.run(_events(EVENT_OK, w.worker_id))]
    details += [r.detail for r in asyncio.run(_events(EVENT_FAIL, w.worker_id))]
    assert details
    for d in details:
        low = d.lower()
        for marker in SECRET_MARKERS:
            assert marker not in low, f"audit detail leaked {marker!r}: {d}"
        assert w.token_hash not in d
        assert (w.cert_fingerprint or "zzz") not in d


def test_the_source_identity_helper_reads_no_secrets():
    """Pinned at the source level: the helper may read a username, a hostname and a pid --
    never an environment value, header, or filesystem path."""
    import inspect

    src = inspect.getsource(scanner_ops._source_identity)
    for forbidden in ("os.environ", "getenv", "open(", "read_text", "subprocess", "Popen"):
        assert forbidden not in src, f"_source_identity must not use {forbidden}"


# =========================================================================================
# TEST 11 -- retries do not create misleading duplicate SUCCESS events
# =========================================================================================

def test_a_retried_reactivation_does_not_produce_two_success_events(disposable):
    """The second attempt loses the conditional UPDATE (the row is no longer `suspended`),
    so it must be recorded as a REFUSAL, not as a second readmission. Otherwise an auditor
    counting successes would see two readmissions where the fleet changed once."""
    w = disposable(status="suspended")

    async def _go(s):
        # First attempt: wins.
        await workers_service.reactivate_worker(s, w.worker_id, reason="first")
        await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="first", actor="a",
            workspace_id=w.workspace_id, site_id=w.site_id)
        await s.commit()
        # Second attempt: the row is 'active' now -> refused.
        with pytest.raises(workers_service.WorkerNotReactivatable) as ei:
            await workers_service.reactivate_worker(s, w.worker_id, reason="retry")
        await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=w.worker_id, reason="retry", actor="a",
            failure=ei.value.reason, observed_status="active")
        await s.commit()
    asyncio.run(_run(_go))

    assert len(asyncio.run(_events(EVENT_OK, w.worker_id))) == 1, "one readmission, one row"
    assert len(asyncio.run(_events(EVENT_FAIL, w.worker_id))) == 1


# =========================================================================================
# best-effort contract + CLI wiring
# =========================================================================================

def test_a_failing_audit_never_breaks_the_operation(monkeypatch, disposable):
    """Rule 1. Recovery during an incident must not depend on the audit path working."""
    async def _boom(*a, **kw):
        raise RuntimeError("audit backend down")

    from apps.api.modules.audit import service as audit_service
    monkeypatch.setattr(audit_service, "record_platform_event", _boom)

    w = disposable(status="suspended")

    async def _go(s):
        worker = await workers_service.reactivate_worker(s, w.worker_id, reason="r")
        ok = await scanner_ops.record_worker_reactivated(
            s, worker_id=w.worker_id, reason="r", actor="a",
            workspace_id=w.workspace_id, site_id=w.site_id)
        failed_ok = await scanner_ops.record_worker_reactivation_failed(
            s, worker_id=w.worker_id, reason="r", actor="a",
            failure="X", observed_status="active")
        await s.commit()
        return worker.status, ok, failed_ok

    status, ok, failed_ok = asyncio.run(_run(_go))
    assert status == "active", "the reactivation itself must still succeed"
    assert ok is False and failed_ok is False, "a failed audit reports False, never raises"


def test_the_cli_audits_both_failure_paths():
    """WIRING GUARD. Both `return 2` (unknown worker) and `return 3` (wrong state) must record
    an attempt -- this is the defect that left refusals invisible, and a future edit that
    reorders the handlers would silently reintroduce it."""
    import inspect

    from apps.api.ops import reactivate_worker as cli

    src = inspect.getsource(cli._reactivate)
    head = src.split("return 2")[0]
    assert "_audit_failure" in head, "the unknown-worker path must audit before returning 2"
    mid = src.split("return 2")[1].split("return 3")[0]
    assert "_audit_failure" in mid, "the wrong-state path must audit before returning 3"


def test_the_failure_audit_helper_is_best_effort_and_commits():
    """A refusal has no other write to ride along with, so its audit row needs its own
    commit -- and that commit must not be able to change the exit code."""
    import inspect

    from apps.api.ops import reactivate_worker as cli

    src = inspect.getsource(cli._audit_failure)
    assert "await db.commit()" in src, "a refusal audit must commit its own row"
    assert "except Exception" in src, "and must never raise into the refusal path"
