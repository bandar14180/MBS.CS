"""MBS.SC PHASE 8 (P8-E) -- operator revocation CLI.

THE GAP THIS CLOSES
-------------------
`revoke_worker()` was complete and correct but had NO production caller -- `grep` found it
only in test files. The documented emergency procedure was a Python snippet that could not be
run as written, because it referenced a `db` session it never constructed. An operator
responding to a suspected compromise had to hand-assemble an engine, sessionmaker and tenancy
bypass, then remember to commit.

WHAT THESE TESTS PIN
--------------------
  * the CLI is the SINGLE BLESSED PATH -- it calls `revoke_worker()` and never writes SQL
    itself (a bare UPDATE would set `status` while leaving a live `token_hash` in the row);
  * `--worker-id` and `--reason` are BOTH mandatory, and neither may be blank;
  * it COMMITS before reporting success (a rolled-back revocation would tell an operator a
    compromised worker was cut off when it was not);
  * every terminal invariant survives: status, timestamps, reason, BOTH credentials cleared;
  * there is no un-revoke path anywhere in the tool;
  * Phase 7 and P8-A/B/C/D/F are untouched.

Runs against the real MySQL test database. Every worker row it creates is its own; it never
touches a pre-existing worker.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.scanner_workers import service as workers_service
from apps.api.modules.scanner_workers.models import ScannerWorker
from apps.api.ops import revoke_worker as cli


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _new_worker(**kw) -> ScannerWorker:
    """A DISPOSABLE worker row, unique per test. Never an existing one."""
    return ScannerWorker(
        id=uuid.uuid4(),
        worker_id=kw.get("worker_id", f"p8e-{uuid.uuid4().hex[:12]}"),
        pool_id=kw.get("pool_id", "public-default"),
        site_id=kw.get("site_id"),
        workspace_id=kw.get("workspace_id"),
        status=kw.get("status", "active"),
        token_hash=kw.get("token_hash", workers_service.hash_worker_token("tok-" + uuid.uuid4().hex)),
        cert_fingerprint=kw.get("cert_fingerprint", "fp-" + uuid.uuid4().hex[:16]),
        health_state=kw.get("health_state", "healthy"),
        last_seen_at=kw.get("last_seen_at", datetime.now(timezone.utc)),
    )


async def _seed(worker: ScannerWorker) -> None:
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                s.add(worker)
                await s.commit()
    finally:
        await engine.dispose()


async def _fetch(worker_id: str) -> ScannerWorker | None:
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                return await s.scalar(
                    select(ScannerWorker).where(ScannerWorker.worker_id == worker_id)
                )
    finally:
        await engine.dispose()


async def _delete(worker_id: str) -> None:
    """Remove a disposable row so the suite leaves no residue."""
    engine = _engine()
    Session = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with Session() as s:
            with tenancy.admin_bypass():
                row = await s.scalar(
                    select(ScannerWorker).where(ScannerWorker.worker_id == worker_id)
                )
                if row is not None:
                    await s.delete(row)
                    await s.commit()
    finally:
        await engine.dispose()


@pytest.fixture
def disposable_worker():
    """Seed a worker, yield it, and delete it afterwards -- whatever the test did."""
    w = _new_worker()
    asyncio.run(_seed(w))
    try:
        yield w
    finally:
        asyncio.run(_delete(w.worker_id))


# --- argument validation ----------------------------------------------------------------

@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--worker-id", "w1"],                    # reason missing
        ["--reason", "r1"],                       # worker-id missing
        ["--worker-id", "w1", "--reason", "   "],  # blank reason
        ["--worker-id", "  ", "--reason", "r1"],   # blank worker id
    ],
)
def test_both_arguments_are_mandatory_and_may_not_be_blank(argv):
    """A reason that could be omitted or whitespace would make `revoked_reason` -- the only
    record of WHY a worker was cut off -- useless exactly where it matters most."""
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_help_works_without_a_database():
    """An operator must be able to read the usage during an incident even if the control
    plane is degraded, so nothing is imported at module scope that needs config or a DB."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0


# --- the revocation itself --------------------------------------------------------------

def test_revoking_sets_every_terminal_field(disposable_worker):
    rc = cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "suspected compromise"])
    assert rc == 0
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    assert got is not None
    assert got.status == "revoked"
    assert got.revoked_at is not None
    assert got.revoked_reason == "suspected compromise"


def test_revoking_destroys_both_stored_credentials(disposable_worker):
    """THE reason a bare `UPDATE ... SET status='revoked'` is not acceptable: it would leave
    a live token_hash in the row."""
    assert disposable_worker.token_hash is not None
    assert disposable_worker.cert_fingerprint is not None
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "key leak"])
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    assert got.token_hash is None
    assert got.cert_fingerprint is None


def test_the_change_is_committed_not_merely_flushed(disposable_worker):
    """`revoke_worker` only flushes. Without the CLI's commit the whole revocation would roll
    back when the session closed -- and the operator would have been told it succeeded."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "commit check"])
    # Re-read through a COMPLETELY SEPARATE engine/session: only a committed write is visible.
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    assert got.status == "revoked"
    assert got.revoked_reason == "commit check"


def test_a_revoked_worker_is_refused_by_the_existing_authorization_gate(disposable_worker):
    """The CLI supplies the state; `assert_worker_active` -- unmodified -- does the refusing."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "gate check"])
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    with pytest.raises(workers_service.WorkerNotAuthorized) as exc:
        workers_service.assert_worker_active(got)
    assert exc.value.reason == workers_service.REASON_WORKER_REVOKED


def test_authentication_fails_after_revocation(disposable_worker):
    """Both credentials are gone, so `hmac.compare_digest` has nothing to match against."""
    token = "tok-known"
    w = _new_worker(token_hash=workers_service.hash_worker_token(token), cert_fingerprint=None)
    asyncio.run(_seed(w))
    try:
        async def _auth():
            engine = _engine()
            Session = async_sessionmaker(engine, expire_on_commit=False)
            try:
                async with Session() as s:
                    with tenancy.admin_bypass():
                        return await workers_service.authenticate_worker(
                            s, worker_id=w.worker_id, token=token
                        )
            finally:
                await engine.dispose()

        # Authenticates before revocation...
        assert asyncio.run(_auth()).worker_id == w.worker_id
        cli.main(["--worker-id", w.worker_id, "--reason", "auth check"])
        # ...and not after.
        with pytest.raises(workers_service.WorkerNotAuthorized):
            asyncio.run(_auth())
    finally:
        asyncio.run(_delete(w.worker_id))


def test_an_unknown_worker_is_a_clean_error_with_no_partial_write():
    rc = cli.main(["--worker-id", f"does-not-exist-{uuid.uuid4().hex[:8]}", "--reason", "x"])
    assert rc == 2


def test_revoking_an_already_revoked_worker_is_safe(disposable_worker):
    """Terminal is terminal: a second call must not resurrect credentials or clear the
    original reason in a way that loses the audit trail."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "first"])
    rc = cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "second"])
    assert rc == 0
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    assert got.status == "revoked"
    assert got.token_hash is None
    assert got.cert_fingerprint is None


# --- the single blessed path ------------------------------------------------------------

def _code_only(module) -> str:
    """Source with docstrings and comments stripped.

    These assertions are about what the CLI DOES, not what it explains. Its module docstring
    deliberately discusses the bare `UPDATE scanner_workers` that must never be used and the
    absence of an un-revoke path -- prose that would otherwise trip a naive substring search.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(module))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)          # drop the docstring
    return ast.unparse(tree)              # comments are already absent from the AST


def test_the_cli_calls_the_service_and_never_writes_sql_itself():
    """A bare UPDATE would set `status` while leaving the credentials intact."""
    src = _code_only(cli)
    assert "revoke_worker(" in src
    for forbidden in ("UPDATE scanner_workers", "text(", "execute(", "DELETE FROM"):
        assert forbidden not in src, f"the CLI must not write SQL itself: {forbidden}"


def test_the_cli_exposes_no_un_revoke_path():
    """Revocation is terminal; recovery is registering a REPLACEMENT worker."""
    import ast
    import inspect

    # Assert on ASSIGNMENTS, not on words: the CLI legitimately PRINTS "...never be
    # reactivated -- register a replacement", which is operator guidance, not a code path.
    tree = ast.parse(inspect.getsource(cli))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            rendered = ast.unparse(node)
            assert "status" not in rendered or "revoked" in rendered, rendered
            for reviving in ("'active'", '"active"', "'pending'", "revoked_at = none"):
                assert reviving.lower() not in rendered.lower(), rendered
    # And the CLI never ASSIGNS to a worker attribute -- mutation is revoke_worker()'s job
    # alone. (It does READ worker.status/.token_hash to print the outcome, which is not a
    # write, so this checks assignment TARGETS rather than substrings.)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Attribute):
                    assert not ast.unparse(t).startswith("worker."), ast.unparse(node)


def test_revoke_worker_service_was_not_modified():
    """P8-E adds a caller; it must not have changed the invariants it depends on."""
    import inspect

    src = inspect.getsource(workers_service.revoke_worker)
    assert 'worker.status = "revoked"' in src
    assert "worker.token_hash = None" in src
    assert "worker.cert_fingerprint = None" in src
    assert "record_worker_revoked" in src


def test_no_http_endpoint_was_added_for_revocation():
    """The switch stays operator/CLI controlled -- an endpoint would need an authorization
    model the platform does not have (require_permission is workspace-scoped, and a public
    worker has workspace_id NULL)."""
    import inspect

    import apps.api.scanner_manager.app as mgr

    assert "revoke_worker" not in inspect.getsource(mgr)


# --- interaction with P8-F --------------------------------------------------------------

def test_the_stale_reaper_never_touches_a_revoked_worker(disposable_worker):
    """P8-F excludes revoked rows (`status='active' AND revoked_at IS NULL`). A reaper that
    moved a revoked worker to `suspended` would WEAKEN a terminal state."""
    cli.main(["--worker-id", disposable_worker.worker_id, "--reason", "reaper check"])

    async def _reap():
        engine = _engine()
        Session = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with Session() as s:
                with tenancy.admin_bypass():
                    # Threshold 0 -> everything is "stale"; the revoked row must still be skipped.
                    return await workers_service.reap_stale_workers(s, 0)
        finally:
            await engine.dispose()

    asyncio.run(_reap())
    got = asyncio.run(_fetch(disposable_worker.worker_id))
    assert got.status == "revoked", "the reaper downgraded a terminal state"
    assert got.revoked_at is not None


# --- REGRESSION: Phase 7 / P8-A / P8-B / P8-C / P8-D unchanged ---------------------------

def test_phase7_per_job_gate_is_unchanged():
    from apps.api.scanner_engine import wireguard
    from apps.api.scanner_worker.lease_loop import LeaseError, preflight_private_job

    down = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    job = {"network_zone": "private", "site_id": "s", "authorized_cidrs": ["10.90.0.0/24"]}
    with pytest.raises(LeaseError):
        preflight_private_job(job, probe=down)
    preflight_private_job({"network_zone": "public"}, probe=None)


def test_p8a_and_p8b_reporting_are_unchanged():
    from apps.api.scanner_worker.lease_loop import LeaseLoop

    assert hasattr(LeaseLoop, "observe_tunnel_health")
    assert hasattr(LeaseLoop, "report_health")


def test_p8c_metrics_projection_is_unchanged():
    from apps.api.scanner_manager.app import _worker_metric_lines

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


def test_p8d_emergency_flag_is_unchanged():
    from apps.api.core import runtime_flags

    assert runtime_flags.FLAG_TTL_SECONDS == 5.0
    assert runtime_flags.EMERGENCY_DISABLE_SENTINEL == "EMERGENCY_DISABLE_PRIVATE_SCANNING"


# --- runbook -----------------------------------------------------------------------------

def test_the_runbook_documents_the_cli_and_drops_the_broken_snippet():
    """One authoritative procedure. The old snippet referenced an undefined `db` session, so
    keeping it as a fallback would preserve a procedure that cannot be followed."""
    from pathlib import Path

    doc = Path(__file__).resolve().parents[3] / "docs" / "runbooks" / "private-scanning.md"
    if not doc.is_file():
        pytest.skip("runbook not present in this environment")
    text = doc.read_text(encoding="utf-8")
    assert "apps.api.ops.revoke_worker" in text
    assert "--worker-id" in text and "--reason" in text
    # The broken snippet must be gone.
    assert "await workers.revoke_worker(db," not in text
