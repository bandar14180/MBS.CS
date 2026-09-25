"""Regression suite for incident 615d0e0b -- scanner result persistence and ToolRun lifecycle.

THE INCIDENT THIS EXISTS TO PREVENT
-----------------------------------
Scan 615d0e0b-32a6-4192-95c9-c974c0df62b0 (brightvision-og.com) failed like this:

    katana ran and was OOM-killed, but preserved 30,873 crawled URLs (status: partial)
        -> the worker POSTed that result to /v1/tool-results
        -> one finding was a ~700-character https://wa.me/... share URL
        -> assets.value was VARCHAR(512)  ->  MySQL DataError(1406)
        -> the endpoint returned HTTP 500
        -> ToolRun status + asset ingestion shared ONE transaction, so the rollback
           discarded the write that would have marked katana `partial`
        -> katana stayed `running` in the database permanently
        -> the 500 escaped the worker's executor as an HTTPStatusError
        -> the tool loop unwound: ffuf, arjun, nuclei and nuclei-dast never started
        -> the scan was recorded `failed`

Seven tools had succeeded. The target was scanned. The only thing that actually broke was
our own storage layer -- and it cost the entire scan.

These tests assert REAL DATABASE STATE through the REAL HTTP endpoint against the REAL
MySQL test database, not mocked call counts, because every link in that chain was a place
where the in-memory behaviour and the persisted behaviour diverged.
"""
import asyncio
import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from apps.api.core import tenancy
from apps.api.core.config import get_settings
from apps.api.modules.assets.models import MAX_ASSET_VALUE_LENGTH
from apps.api.modules.assets.service import AssetValueTooLong, validate_asset_value

# The manager_env fixture and its auth helper are already written and battle-tested in the
# HTTP suite; importing them keeps ONE definition of "a correctly seeded tenant" rather than
# a second copy that can drift from the endpoints' real authorization requirements.
#
# F811 is a false positive here: pytest resolves a fixture by NAME in the module namespace,
# so the import is the mechanism, and each test's `manager_env` parameter is a fixture
# request rather than a redefinition. (conftest.py is the usual home for a shared fixture
# for exactly this reason; this one is deliberately left where it is, next to the endpoint
# suite whose seeding requirements it encodes.)
from apps.api.tests.test_scanner_manager_http import _auth, manager_env  # noqa: F401, F811


# The exact value that broke the real scan, reconstructed to the same shape and length: a
# WhatsApp share link whose ?text= parameter carries a URL-encoded marketing message.
INCIDENT_URL = (
    "https://wa.me/60176237619?text=University%20of%20Cyberjaya%20%28UOC%29%0A%0A"
    "DOCTOR%20IN%20BUSINESS%20ADMINISTRATION%20-%20ODL%0A%0A-%20Duration%3A%20"
    + "%20".join(["Module%20Detail%20Text"] * 20)
    + "%0A%0Aabout%20the%20program%3A%0Ahttps%3A//universities.brightvision-og.com"
    "/university/university-of-cyberjaya-uoc/doctor-in-business-administration-odl/"
)


def _engine():
    return create_async_engine(get_settings().database_url, poolclass=StaticPool)


def _post_result(client, entry, *, tool_run_id, status="completed", findings=None,
                 tool_name="nuclei"):
    return client.post("/v1/tool-results", headers=_auth(entry), json={
        "scan_id": str(entry["scan_id"]),
        "tool_run_id": str(tool_run_id),
        "tool_name": tool_name,
        "execution_token": str(entry["execution_token"]),
        "status": status,
        "findings": findings if findings is not None else [],
    })


def _url_finding(value: str):
    return {"asset_type": "url", "value": value, "metadata": {"source": "katana"}}


def _query(sql: str, params: dict):
    """Read committed state back on a FRESH engine/connection.

    Deliberately not the request's session: the whole point of these assertions is what is
    durably COMMITTED and visible to another connection, which is what the UI and the next
    worker actually see.
    """
    async def go():
        engine = _engine()
        try:
            Session = async_sessionmaker(engine, expire_on_commit=False)
            async with Session() as s:
                with tenancy.admin_bypass():
                    return (await s.execute(text(sql), params)).fetchall()
        finally:
            await engine.dispose()

    return asyncio.run(go())


# =======================================================================================
# 1. ASSET VALUE -- the trigger. Length boundary, no truncation.
# =======================================================================================

def test_incident_url_exceeds_the_old_limit_and_fits_the_new_one():
    """Anchors the fix to the real data: the URL that broke production is >512 and <=2048."""
    assert len(INCIDENT_URL) > 512, "regression value no longer reproduces the incident"
    assert len(INCIDENT_URL) <= MAX_ASSET_VALUE_LENGTH


def test_validate_accepts_a_normal_url():
    assert validate_asset_value("https://brightvision-og.com/about") is not None


def test_validate_accepts_exactly_512_characters():
    """512 was the OLD ceiling; it must remain perfectly valid, not become a boundary."""
    value = "https://x.test/" + "a" * (512 - len("https://x.test/"))
    assert len(value) == 512
    assert validate_asset_value(value) == value


def test_validate_accepts_513_characters():
    """The first length the old column rejected."""
    value = "https://x.test/" + "a" * (513 - len("https://x.test/"))
    assert len(value) == 513
    assert validate_asset_value(value) == value


def test_validate_accepts_exactly_the_new_maximum():
    value = "https://x.test/" + "a" * (MAX_ASSET_VALUE_LENGTH - len("https://x.test/"))
    assert len(value) == MAX_ASSET_VALUE_LENGTH
    assert validate_asset_value(value) == value


def test_validate_rejects_one_character_over_the_maximum():
    value = "a" * (MAX_ASSET_VALUE_LENGTH + 1)
    with pytest.raises(AssetValueTooLong) as exc:
        validate_asset_value(value)
    assert exc.value.length == MAX_ASSET_VALUE_LENGTH + 1
    assert exc.value.limit == MAX_ASSET_VALUE_LENGTH


def test_validation_never_truncates():
    """A truncated URL is not the URL that was observed.

    Storing `value[:2048]` would fabricate evidence: a link nobody can follow, which can
    also collide with a genuinely different asset under the uniqueness key. The contract is
    reject-and-log, never silently shorten -- so an over-long value must RAISE rather than
    come back shortened.
    """
    value = "https://x.test/" + "b" * MAX_ASSET_VALUE_LENGTH
    with pytest.raises(AssetValueTooLong):
        validate_asset_value(value)


# =======================================================================================
# 2. THE INCIDENT, END TO END, THROUGH THE REAL ENDPOINT
# =======================================================================================

def test_incident_url_now_persists_and_does_not_500(manager_env):  # noqa: F811
    """The exact failure that started it all: this POST used to return 500."""
    client, state = manager_env
    tool_run_id = uuid.uuid4()
    r = _post_result(client, state["a"], tool_run_id=tool_run_id, status="partial",
                     findings=[_url_finding(INCIDENT_URL)])
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 1
    assert r.json()["rejected_assets"] == 0

    stored = _query(
        "SELECT value FROM assets WHERE target_id = :t AND asset_type = 'url'",
        {"t": str(_scan_target(state["a"]))},
    )
    values = [row[0] for row in stored]
    assert INCIDENT_URL in values, "the URL must be stored verbatim, not truncated"


def _scan_target(entry):
    rows = _query("SELECT target_id FROM scans WHERE id = :s", {"s": str(entry["scan_id"])})
    return rows[0][0]


def test_toolrun_reaches_a_terminal_state_even_when_an_asset_is_unstorable(manager_env):  # noqa: F811
    """INVARIANT A/B/D -- the heart of the incident.

    An asset that cannot be stored must not cost the ToolRun its terminal status. Before
    the fix this exact submission left the row `running` forever.
    """
    client, state = manager_env
    tool_run_id = uuid.uuid4()
    oversized = "https://x.test/" + "c" * (MAX_ASSET_VALUE_LENGTH + 500)

    r = _post_result(client, state["a"], tool_run_id=tool_run_id, status="partial",
                     findings=[_url_finding(oversized)])
    assert r.status_code == 200, r.text
    assert r.json()["rejected_assets"] == 1
    assert r.json()["assets"] == 0

    rows = _query(
        "SELECT status, completed_at FROM tool_runs WHERE id = :i", {"i": str(tool_run_id)}
    )
    assert rows, "the ToolRun row must exist"
    assert rows[0][0] == "partial", (
        "ToolRun status was rolled back by the asset failure -- this is incident 615d0e0b"
    )
    assert rows[0][1] is not None, "a terminal ToolRun must have completed_at stamped"


def test_valid_assets_survive_an_invalid_one(manager_env):  # noqa: F811
    """INVARIANT C -- per-asset savepoint isolation.

    Without savepoints the first DataError poisons the transaction and every LATER finding
    fails too, so one bad URL out of 500 would still lose the other 499.
    """
    client, state = manager_env
    tool_run_id = uuid.uuid4()
    good_before = "https://brightvision-og.com/before"
    good_after = "https://brightvision-og.com/after"
    oversized = "https://x.test/" + "d" * (MAX_ASSET_VALUE_LENGTH + 100)

    r = _post_result(client, state["a"], tool_run_id=tool_run_id, status="completed",
                     findings=[
                         _url_finding(good_before),
                         _url_finding(oversized),
                         _url_finding(good_after),
                     ])
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 2
    assert r.json()["rejected_assets"] == 1

    stored = {row[0] for row in _query(
        "SELECT value FROM assets WHERE target_id = :t AND asset_type = 'url'",
        {"t": str(_scan_target(state["a"]))},
    )}
    assert good_before in stored, "an asset BEFORE the bad one was lost"
    assert good_after in stored, (
        "an asset AFTER the bad one was lost -- the failure poisoned the transaction"
    )
    assert oversized not in stored


def test_duplicate_assets_still_dedupe_through_the_hash_key(manager_env):  # noqa: F811
    """The uniqueness grain must be unchanged by moving the key onto a generated hash."""
    client, state = manager_env
    url = "https://brightvision-og.com/dedupe-me"
    for _ in range(2):
        r = _post_result(client, state["a"], tool_run_id=uuid.uuid4(), status="completed",
                         findings=[_url_finding(url)])
        assert r.status_code == 200, r.text

    rows = _query(
        "SELECT COUNT(*) FROM assets WHERE target_id = :t AND asset_type = 'url' "
        "AND value = :v",
        {"t": str(_scan_target(state["a"])), "v": url},
    )
    assert rows[0][0] == 1, "the same asset was stored twice -- dedup semantics changed"


def test_long_urls_differing_only_past_512_chars_are_distinct_assets(manager_env):  # noqa: F811
    """Proves the key really covers the FULL value, not a 512-char prefix.

    A prefix index would have silently merged these two genuinely different URLs.
    """
    client, state = manager_env
    base = "https://brightvision-og.com/?q=" + "e" * 600
    a, b = base + "AAA", base + "BBB"
    r = _post_result(client, state["a"], tool_run_id=uuid.uuid4(), status="completed",
                     findings=[_url_finding(a), _url_finding(b)])
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 2

    rows = _query(
        "SELECT COUNT(*) FROM assets WHERE target_id = :t AND value LIKE :p",
        {"t": str(_scan_target(state["a"])), "p": base[:200] + "%"},
    )
    assert rows[0][0] == 2, "two distinct long URLs collapsed into one row"


def test_a_completed_toolrun_is_not_reverted_by_a_later_asset_failure(manager_env):  # noqa: F811
    """INVARIANT A, stated directly: `completed` must never fall back to `running`."""
    client, state = manager_env
    tool_run_id = uuid.uuid4()
    oversized = "https://x.test/" + "f" * (MAX_ASSET_VALUE_LENGTH + 10)
    r = _post_result(client, state["a"], tool_run_id=tool_run_id, status="completed",
                     findings=[_url_finding(oversized)])
    assert r.status_code == 200, r.text

    rows = _query("SELECT status FROM tool_runs WHERE id = :i", {"i": str(tool_run_id)})
    assert rows[0][0] == "completed"


# =======================================================================================
# 2b. THE STRUCTURAL DEFENCES, EXERCISED AGAINST A REAL DRIVER-LEVEL FAILURE
#
# The tests above are satisfied by the length VALIDATION alone: `validate_asset_value`
# raises before any SQL is issued, so the transaction is never poisoned and the split
# commit / savepoints are never actually put under load.
#
# That makes them insufficient on their own. Validation is one guess about which values are
# unstorable, and the incident proves such guesses can be wrong -- the column limit was a
# surprise precisely because nobody had enumerated it. The transaction boundaries exist so
# that an UNANTICIPATED persistence failure is survivable too.
#
# These tests therefore bypass the Python guard and force a genuine DataError from MySQL,
# reproducing the original failure mode exactly. Verified to FAIL when either structural fix
# is reverted (see the remediation report's mutation-testing section).
# =======================================================================================

@pytest.fixture
def _oversized_passes_validation(monkeypatch):
    """Neuter the length guard so the value reaches MySQL and the driver raises 1406 --
    exactly what happened in production before the column was widened."""
    import apps.api.modules.assets.service as assets_service

    monkeypatch.setattr(assets_service, "validate_asset_value", lambda value: value)
    return True


def test_toolrun_survives_a_real_driver_level_dataerror(
    manager_env, _oversized_passes_validation,  # noqa: F811
):
    """INVARIANT D against the REAL failure: a DataError raised by MySQL itself.

    This is incident 615d0e0b reproduced faithfully. With the ToolRun status sharing the
    asset transaction, this submission left the row `running` forever.
    """
    client, state = manager_env
    tool_run_id = uuid.uuid4()
    # Past the COLUMN limit, so MySQL -- not Python -- rejects it.
    oversized = "https://x.test/" + "g" * (MAX_ASSET_VALUE_LENGTH + 1000)

    r = _post_result(client, state["a"], tool_run_id=tool_run_id, status="partial",
                     findings=[_url_finding(oversized)])
    assert r.status_code == 200, r.text
    assert r.json()["rejected_assets"] == 1

    rows = _query("SELECT status FROM tool_runs WHERE id = :i", {"i": str(tool_run_id)})
    assert rows and rows[0][0] == "partial", (
        "a driver-level DataError rolled back the ToolRun status -- incident 615d0e0b"
    )


def test_good_assets_survive_a_real_driver_level_dataerror(
    manager_env, _oversized_passes_validation,  # noqa: F811
):
    """INVARIANT C against the REAL failure -- the case savepoints exist for.

    A failed statement puts the transaction into 'must rollback' state, so WITHOUT a
    savepoint every finding after the bad one fails too. This is the test that proves the
    savepoint is load-bearing rather than decorative.
    """
    client, state = manager_env
    good_before = "https://brightvision-og.com/db-before"
    good_after = "https://brightvision-og.com/db-after"
    oversized = "https://x.test/" + "h" * (MAX_ASSET_VALUE_LENGTH + 1000)

    r = _post_result(client, state["a"], tool_run_id=uuid.uuid4(), status="completed",
                     findings=[
                         _url_finding(good_before),
                         _url_finding(oversized),
                         _url_finding(good_after),
                     ])
    assert r.status_code == 200, r.text
    assert r.json()["assets"] == 2
    assert r.json()["rejected_assets"] == 1

    stored = {row[0] for row in _query(
        "SELECT value FROM assets WHERE target_id = :t AND asset_type = 'url'",
        {"t": str(_scan_target(state["a"]))},
    )}
    assert good_before in stored
    assert good_after in stored, (
        "the asset AFTER the DataError was lost -- the poisoned transaction was not "
        "contained by a savepoint"
    )


def test_a_real_dataerror_does_not_500_the_endpoint(
    manager_env, _oversized_passes_validation,  # noqa: F811
):
    """The 500 is what escaped into the worker and unwound the pipeline. It must not
    happen even when the failure originates in the driver."""
    client, state = manager_env
    oversized = "https://x.test/" + "i" * (MAX_ASSET_VALUE_LENGTH + 1000)
    r = _post_result(client, state["a"], tool_run_id=uuid.uuid4(), status="partial",
                     findings=[_url_finding(oversized)])
    assert r.status_code == 200, f"endpoint 500'd on an unstorable asset: {r.text}"


def test_toolrun_status_is_durable_even_if_asset_ingestion_dies_outright(manager_env):  # noqa: F811
    """INVARIANT D at its strongest, and the test that pins the SPLIT COMMIT specifically.

    The tests above are survived by per-item error handling alone. This one is not: asset
    ingestion is made to fail wholesale, and the surrounding request still has to leave
    katana's terminal status committed. That can only hold if the ToolRun write was
    committed BEFORE ingestion began.

    The failure is injected at the INGESTION COMMIT -- deliberately outside the per-asset
    `except`, which would otherwise absorb it and let the request finish normally. Revert
    the early `await db.commit()` in /v1/tool-results and this test fails with the ToolRun
    still 'running', which is incident 615d0e0b exactly.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    client, state = manager_env
    tool_run_id = uuid.uuid4()

    real_commit = AsyncSession.commit
    seen = {"n": 0}

    async def _commit(self):
        seen["n"] += 1
        # Let the FIRST commit (the ToolRun's terminal state) through; blow up on the
        # SECOND (asset ingestion). With the fix, the status is already durable by then.
        if seen["n"] >= 2:
            raise RuntimeError("ingestion commit failed")
        return await real_commit(self)

    AsyncSession.commit = _commit
    try:
        try:
            _post_result(client, state["a"], tool_run_id=tool_run_id, status="partial",
                         findings=[_url_finding("https://brightvision-og.com/x")])
        except RuntimeError:
            # The injected failure may surface as an unhandled server error; irrelevant to
            # what is being asserted, which is purely what remained COMMITTED.
            pass
    finally:
        AsyncSession.commit = real_commit

    assert seen["n"] >= 2, "the endpoint did not perform two separate commits"
    rows = _query("SELECT status FROM tool_runs WHERE id = :i", {"i": str(tool_run_id)})
    assert rows and rows[0][0] == "partial", (
        "the ToolRun's terminal status did not survive an asset-ingestion commit failure -- "
        "the status write is still sharing a transaction with ingestion"
    )


# =======================================================================================
# 3. RESULTSINK -- bounded retry, correct retryability classification
# =======================================================================================

class _ScriptedClient:
    """Minimal stand-in for httpx.AsyncClient that replays a scripted sequence."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls = 0

    async def post(self, url, headers=None, json=None, files=None):  # noqa: ANN001
        self.calls += 1
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {"ok": True}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"{self.status_code}", request=httpx.Request("POST", "http://m/x"),
                response=httpx.Response(self.status_code, request=httpx.Request("POST", "http://m/x")),
            )


def _sink(client):
    from apps.api.scanner_engine.result_sink import ManagerResultSink

    return ManagerResultSink(
        manager_url="http://manager:8100", worker_id="wk-test", token="t", client=client
    )


def _submit(sink):
    return asyncio.run(sink.submit_tool_result(
        scan_id=uuid.uuid4(), tool_run_id=uuid.uuid4(), status="completed", findings=[],
        tool_name="nuclei",
    ))


def test_sink_returns_immediately_on_success():
    client = _ScriptedClient([_Resp(200)])
    assert _submit(_sink(client))["ok"] is True
    assert client.calls == 1


def test_sink_retries_a_500_and_succeeds():
    client = _ScriptedClient([_Resp(500), _Resp(200)])
    assert _submit(_sink(client))["ok"] is True
    assert client.calls == 2, "a transient 500 must be retried"


def test_sink_retry_is_bounded_and_then_raises():
    """Bounded: the worker must not turn a struggling manager into a retry storm."""
    from apps.api.scanner_engine.result_sink import _POST_MAX_ATTEMPTS

    client = _ScriptedClient([_Resp(500)] * _POST_MAX_ATTEMPTS)
    with pytest.raises(httpx.HTTPStatusError):
        _submit(_sink(client))
    assert client.calls == _POST_MAX_ATTEMPTS


def test_sink_retries_a_connection_error():
    client = _ScriptedClient([httpx.ConnectError("reset"), _Resp(200)])
    assert _submit(_sink(client))["ok"] is True
    assert client.calls == 2


def test_sink_retries_a_timeout():
    client = _ScriptedClient([httpx.ReadTimeout("slow"), _Resp(200)])
    assert _submit(_sink(client))["ok"] is True
    assert client.calls == 2


def test_sink_does_not_retry_a_permanent_4xx():
    """403 is a verdict about THIS request -- a superseded token or a revoked worker.

    Re-sending identical bytes earns an identical refusal, so retrying only delays the
    caller's own error handling.
    """
    client = _ScriptedClient([_Resp(403)])
    with pytest.raises(httpx.HTTPStatusError):
        _submit(_sink(client))
    assert client.calls == 1


def test_sink_retries_a_429_because_it_means_later_not_no():
    client = _ScriptedClient([_Resp(429), _Resp(200)])
    assert _submit(_sink(client))["ok"] is True
    assert client.calls == 2


# =======================================================================================
# 4. PIPELINE -- a persistence failure must not stop the scan
# =======================================================================================

class _FakeRaw:
    def __init__(self, stdout="", exit_code=0):
        self.stdout = stdout
        self.stderr = ""
        self.exit_code = exit_code
        self.command = "fake"


def _make_runner_class():
    """Build a runner on the REAL BaseToolRunner.

    Subclassed rather than duck-typed so the executor's genuine `classify_run` path runs
    (hard_failure/benign_exit_codes and all) -- a hand-rolled stub would let the test pass
    against an interface the production code does not actually use.
    """
    from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding

    class _FakeRunner(BaseToolRunner):
        applicable_target_types = None

        def __init__(self, name, executed, phase=1):
            self.name = name
            self.version = "0.0.0"
            self.phase = phase
            self._executed = executed

        async def run(self, target_value, config, discovered):  # noqa: ANN001
            self._executed.append(self.name)
            return _FakeRaw(stdout="https://x.test/found")

        def parse(self, raw):  # noqa: ANN001
            return [CommonFinding(
                asset_type="url", value="https://x.test/found", metadata={}
            )]

    return _FakeRunner


class _AlwaysFailingReporter:
    """Every result submission fails, as the manager's 500 did during the incident."""

    def __init__(self):
        self.attempts = []

    async def submit_tool_started(self, **kw):
        return {"ok": True}

    async def submit_tool_result(self, **kw):
        self.attempts.append(kw.get("tool_name"))
        raise httpx.HTTPStatusError(
            "500", request=httpx.Request("POST", "http://m/x"),
            response=httpx.Response(500, request=httpx.Request("POST", "http://m/x")),
        )

    async def submit_evidence(self, **kw):
        return {"ok": True}


def _run_pipeline(registry, reporter, modules):
    from apps.api.scanner_engine import net_guard as _ng  # noqa: F401
    from apps.api.scanner_worker.executor import execute_leased_job

    job = {
        "scan_id": str(uuid.uuid4()),
        "execution_token": str(uuid.uuid4()),
        "target": {"value": "example.test", "type": "domain"},
        "requested_modules": modules,
        "config": {},
    }
    return asyncio.run(execute_leased_job(job, None, reporter=reporter, registry=registry))


def test_every_later_tool_still_runs_when_a_result_submission_fails():
    """THE CORE PIPELINE RULE.

    This is the incident reproduced at the executor: tool A's submission fails, and B, C
    and D must still execute. Before the fix the HTTPStatusError unwound the loop and
    ffuf/arjun/nuclei/nuclei-dast never started.
    """
    executed = []
    names = ["katana", "ffuf", "arjun", "nuclei"]
    runner_cls = _make_runner_class()
    # Distinct ascending phases so the executor's deterministic sort preserves this order,
    # which is what lets the assertion below prove the pipeline did not stop early.
    registry = {
        n: (lambda n=n, i=i: runner_cls(n, executed, phase=i))
        for i, n in enumerate(names)
    }

    reporter = _AlwaysFailingReporter()
    status = _run_pipeline(registry, reporter, names)

    assert executed == names, (
        f"pipeline stopped early after a persistence failure: ran {executed}, expected {names}"
    )
    assert reporter.attempts == names, "every tool should still have attempted submission"
    # The tools RAN, so the scan is NOT `failed` -- reporting failure would claim the target
    # was never scanned. It is `completed_with_errors`, not a clean `completed`: the results
    # were lost, so `tool_runs` cannot corroborate the run and this must stay distinguishable
    # from a scan that genuinely persisted everything (executor.py's scan-level analogue of
    # F2-09). Asserting a bare "completed" here would let lost results look like clean coverage.
    assert status == "completed_with_errors"


def test_a_persistence_failure_alone_does_not_fail_the_scan():
    """A scan whose tools all ran must not be reported `failed` because storage broke.

    Marking it failed would tell the operator the target was not scanned, which is false --
    and is exactly the misreport that made incident 615d0e0b look like a katana bug.
    """
    executed = []
    runner_cls = _make_runner_class()
    registry = {"nuclei": lambda: runner_cls("nuclei", executed)}
    status = _run_pipeline(registry, _AlwaysFailingReporter(), ["nuclei"])
    assert executed == ["nuclei"]
    # Not `failed` -- that is the invariant this test exists for. `completed_with_errors`
    # rather than `completed` because the result was lost (see the sibling test above).
    assert status != "failed"
    assert status == "completed_with_errors"


def test_submit_helper_never_raises():
    """`_submit_tool_result_resilient` is the single choke point; it must swallow nothing
    silently but must also never propagate."""
    from apps.api.scanner_worker.executor import _submit_tool_result_resilient

    ok = asyncio.run(_submit_tool_result_resilient(
        _AlwaysFailingReporter(), scan_id=uuid.uuid4(), tool_run_id=uuid.uuid4(),
        tool_name="katana", status="partial", findings=[],
    ))
    assert ok is False, "a failed submission must report False, not raise"
