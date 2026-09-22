"""Regression coverage: the worker's derived-scope check must not block the event loop.

WHAT BROKE
----------
`scanner_worker/executor.py` called `scope_guard.partition_in_scope()` SYNCHRONOUSLY from
`execute_leased_job`, which is a coroutine on the worker's only event loop. It descends
into `net_guard.resolve_hostname()` -> `socket.getaddrinfo()`, which additionally
`time.sleep()`s between its retry attempts. A scan carrying many unresolvable derived
hosts therefore held the loop for minutes at a stretch.

The same loop carries `lease_loop._heartbeat_while_running`, so the beat could not run:
`scans.last_heartbeat_at` went unstamped for 13m46s, the manager suspended the worker as
unresponsive and the stale-scan reaper cascaded off that.

The fix moves that ONE call onto `asyncio.to_thread`. Nothing about the scope rules,
`resolve_hostname`'s retry/backoff, or the fail-closed verdicts changed -- only the
thread it runs on. These tests pin both halves of that: the loop stays live while scope
resolution blocks, AND every existing scope/DNS semantic still holds. They also pin the
boundary of the fix -- which neighbouring call resolves DNS and which does not.

DETERMINISTIC BY CONSTRUCTION
-----------------------------
No test here touches real DNS or any external name. Blocking is simulated with
`time.sleep` against a monkeypatched `net_guard.resolve_hostname`, so
the timing assertions do not depend on a resolver, a network, or wall-clock luck.
"""
import asyncio
import socket
import time

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard, scope_guard
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_worker import executor as executor_mod

# _job()'s target below is domain "t.example.com":
#   - "sub.t.example.com" is IN scope   (subdomain of the target)
#   - "evil.attacker.com" is OUT of scope (unrelated domain)
TARGET_DOMAIN = "t.example.com"


def _job(modules=("nuclei",)) -> dict:
    return {
        "scan_id": "11111111-1111-1111-1111-111111111111",
        "execution_token": "22222222-2222-2222-2222-222222222222",
        "target": {"id": "t", "type": "domain", "value": TARGET_DOMAIN},
        "requested_modules": list(modules),
        "config": {},
    }


def _runner(name, phase, result: RawToolOutput, findings=None):
    class _StubRunner:
        pass

    _StubRunner.name = name
    _StubRunner.phase = phase
    _StubRunner.applicable_target_types = None
    _StubRunner.benign_exit_codes = ()

    captured: dict = {}

    async def run(self, target_value, config, prior):
        captured["prior_findings"] = list(prior)
        return result

    def parse(self, raw):
        return list(findings or [])

    def hard_failure_fn(self, raw):
        return False

    _StubRunner.run = run
    _StubRunner.parse = parse
    _StubRunner.hard_failure = hard_failure_fn
    return _StubRunner, captured


def _ok(stdout="ok"):
    return RawToolOutput(command="x", stdout=stdout, stderr="", exit_code=0)


# =========================================================================================
# 1. A BLOCKING partition_in_scope must not prevent a concurrent asyncio task from running.
#
#    This is the actual defect. The heartbeat is modelled by a plain asyncio task ticking
#    on a short interval -- the same shape as lease_loop._heartbeat_while_running, which is
#    an `asyncio.ensure_future(...)` sibling of the awaited executor coroutine.
# =========================================================================================

BLOCK_SECONDS = 0.6
BEAT_INTERVAL = 0.02


def _blocking_resolver(seconds: float, calls: list):
    """Stand-in for net_guard.resolve_hostname that blocks the calling THREAD.

    Mirrors the real failure mode: getaddrinfo stalls, then time.sleep() backs off, then
    it raises gaierror -- which scope_guard catches and turns into "out of scope"."""
    def _resolve(host, *args, **kwargs):
        calls.append(host)
        time.sleep(seconds)
        raise socket.gaierror(socket.EAI_NONAME, "deterministic stub: no resolution")
    return _resolve


@pytest.mark.parametrize("enforce", [True])
def test_blocking_scope_resolution_does_not_starve_a_concurrent_heartbeat(monkeypatch, enforce):
    """THE REGRESSION. While scope resolution blocks for BLOCK_SECONDS, a concurrent
    asyncio task must keep getting scheduled.

    Before the fix the executor called partition_in_scope() inline, so the loop was held
    for the whole blocking window and the beat ticked ZERO times. After the fix the work
    runs on a thread and the beat keeps ticking throughout."""
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_enforce_derived_scope", enforce)

    calls: list = []
    monkeypatch.setattr(
        net_guard, "resolve_hostname", _blocking_resolver(BLOCK_SECONDS, calls)
    )

    # An IP-valued finding forces the resolution path: scope_guard must resolve the target
    # domain to decide whether this address belongs to it (_hostname_resolves_to).
    upstream_cls, _ = _runner(
        "httpx", 20, _ok(), findings=[CommonFinding(asset_type="ip", value="203.0.113.7")]
    )
    downstream_cls, downstream_captured = _runner("nuclei", 50, _ok())

    beats: list[float] = []

    async def _heartbeat():
        """Stands in for lease_loop._heartbeat_while_running: a sibling task on the same
        loop that must keep running while the scan executes."""
        try:
            while True:
                await asyncio.sleep(BEAT_INTERVAL)
                beats.append(time.monotonic())
        except asyncio.CancelledError:
            return

    async def _scenario():
        beat = asyncio.ensure_future(_heartbeat())
        try:
            return await executor_mod.execute_leased_job(
                _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
                registry={"httpx": upstream_cls, "nuclei": downstream_cls},
            )
        finally:
            beat.cancel()
            try:
                await beat
            except asyncio.CancelledError:
                pass

    started = time.monotonic()
    asyncio.run(_scenario())
    elapsed = time.monotonic() - started

    # The blocking resolver really was exercised -- otherwise this test proves nothing.
    assert calls, "expected scope resolution to hit the (stubbed) resolver"
    # 0.9x, not 1.0x: Windows' timer granularity lets time.sleep(0.6) return at ~0.593s.
    # This only needs to prove the stub really blocked, not to measure it precisely.
    assert elapsed >= BLOCK_SECONDS * 0.9, "expected the stub to actually block"

    # The heartbeat kept running DURING the block. Generous floor (a quarter of the ticks
    # the interval allows) so this is robust on a loaded CI box while still failing hard
    # against the pre-fix behavior, which produced zero beats in this window.
    expected = BLOCK_SECONDS / BEAT_INTERVAL
    assert len(beats) >= expected / 4, (
        f"heartbeat starved: {len(beats)} beats in {elapsed:.2f}s "
        f"(event loop was blocked by synchronous scope/DNS work)"
    )

    # And the gap between consecutive beats never approached the blocking window: no single
    # stall swallowed the loop.
    gaps = [b - a for a, b in zip(beats, beats[1:])]
    if gaps:
        assert max(gaps) < BLOCK_SECONDS / 2, (
            f"longest heartbeat gap {max(gaps):.2f}s -- the loop stalled"
        )

    # Fail-closed outcome preserved: an unresolvable IP finding is NOT handed to the
    # downstream active tool.
    assert downstream_captured["prior_findings"] == []


def test_derived_scope_roots_does_not_resolve_and_so_needs_no_offload(monkeypatch):
    """Pins WHY only `partition_in_scope` is offloaded in the executor.

    `derived_scope_roots` inspects only NAMED (non-IP) hosts. For those, `host_in_scope`
    either matches by suffix (no lookup) or falls through to `_hostname_resolves_to`, whose
    `_is_ip(ip_value)` guard rejects a non-IP argument BEFORE resolving. So it never touches
    the resolver and never blocks the loop -- which is why it is left as a direct call.

    If this assertion ever fails, `derived_scope_roots` has gained a resolving path and the
    executor's call to it must be offloaded too."""
    calls: list = []
    monkeypatch.setattr(net_guard, "resolve_hostname", _blocking_resolver(0.0, calls))

    roots = scope_guard.derived_scope_roots(
        "domain", TARGET_DOMAIN,
        [
            CommonFinding(asset_type="subdomain", value="sub.t.example.com"),
            CommonFinding(asset_type="subdomain", value="other.example.net"),
            CommonFinding(asset_type="ip", value="203.0.113.9"),
        ],
    )
    assert roots == frozenset({"sub.t.example.com"})
    assert calls == [], (
        "derived_scope_roots now resolves DNS -- it must be offloaded in executor.py"
    )


def test_partition_in_scope_does_resolve_on_both_blocking_shapes(monkeypatch):
    """The converse: `partition_in_scope` DOES resolve, on both real-world shapes --
    an IP finding under a domain target (naabu/nmap output) and a hostname finding under
    an ip_range target. This is what justifies the offload."""
    calls: list = []
    monkeypatch.setattr(net_guard, "resolve_hostname", _blocking_resolver(0.0, calls))

    scope_guard.partition_in_scope(
        "domain", TARGET_DOMAIN, [CommonFinding(asset_type="ip", value="203.0.113.7")]
    )
    assert calls == [TARGET_DOMAIN]

    calls.clear()
    scope_guard.partition_in_scope(
        "ip_range", "10.0.0.0/24",
        [CommonFinding(asset_type="subdomain", value="h.example.com")],
    )
    assert calls == ["h.example.com"]


# =========================================================================================
# 2 / 4 / 5. Scope filtering semantics are UNCHANGED by the offload.
#
#    Asserted here directly against the executor with a deterministic resolver stub, so a
#    future change to the offload mechanics cannot quietly alter the verdicts.
# =========================================================================================

def _no_resolution(monkeypatch):
    """Deterministic resolver: every name fails to resolve, instantly. Keeps the name-based
    scope branches (which is all these cases need) free of any real DNS."""
    def _resolve(host, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "deterministic stub: no resolution")
    monkeypatch.setattr(net_guard, "resolve_hostname", _resolve)


def test_out_of_scope_target_remains_excluded(monkeypatch):
    _no_resolution(monkeypatch)
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)
    upstream_cls, _ = _runner(
        "httpx", 20, _ok(),
        findings=[CommonFinding(asset_type="subdomain", value="evil.attacker.com")],
    )
    downstream_cls, captured = _runner("nuclei", 50, _ok())
    asyncio.run(executor_mod.execute_leased_job(
        _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert captured["prior_findings"] == []


def test_in_scope_target_remains_included(monkeypatch):
    _no_resolution(monkeypatch)
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)
    upstream_cls, _ = _runner(
        "httpx", 20, _ok(),
        findings=[CommonFinding(asset_type="subdomain", value="sub.t.example.com")],
    )
    downstream_cls, captured = _runner("nuclei", 50, _ok())
    asyncio.run(executor_mod.execute_leased_job(
        _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert len(captured["prior_findings"]) == 1
    assert captured["prior_findings"][0].value == "sub.t.example.com"


def test_mixed_batch_partitions_exactly_as_before(monkeypatch):
    """Order-preserving partition across a mixed batch -- the in-scope subset handed to the
    downstream tool is identical to what a DIRECT (non-offloaded) call produces."""
    _no_resolution(monkeypatch)
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)
    batch = [
        CommonFinding(asset_type="subdomain", value="a.t.example.com"),
        CommonFinding(asset_type="subdomain", value="evil.attacker.com"),
        CommonFinding(asset_type="subdomain", value="b.t.example.com"),
        CommonFinding(asset_type="subdomain", value="t.example.com.evil.com"),
    ]
    upstream_cls, _ = _runner("httpx", 20, _ok(), findings=batch)
    downstream_cls, captured = _runner("nuclei", 50, _ok())
    asyncio.run(executor_mod.execute_leased_job(
        _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))

    # The direct, synchronous reference verdict for the same inputs.
    reference, _out = scope_guard.partition_in_scope("domain", TARGET_DOMAIN, batch)
    assert [f.value for f in captured["prior_findings"]] == [f.value for f in reference]
    assert [f.value for f in captured["prior_findings"]] == [
        "a.t.example.com", "b.t.example.com"
    ]


# =========================================================================================
# 3. DNS resolution failure/retry behavior is untouched.
# =========================================================================================

def test_resolve_hostname_retry_and_backoff_are_unchanged(monkeypatch):
    """`resolve_hostname` still retries `attempts` times with the same linear backoff and
    still RAISES on a genuinely unresolvable host. The fix must not have relaxed this."""
    attempts_seen: list = []
    sleeps: list[float] = []

    def _getaddrinfo(host, port, *args, **kwargs):
        attempts_seen.append(host)
        raise socket.gaierror(socket.EAI_NONAME, "deterministic stub")

    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _getaddrinfo)
    monkeypatch.setattr(net_guard.time, "sleep", lambda s: sleeps.append(s))

    with pytest.raises(Exception):
        net_guard.resolve_hostname("nope.invalid", attempts=3, retry_backoff_seconds=0.2)

    assert len(attempts_seen) == 3, "retry count changed"
    # Linear backoff between attempts: 0.2, 0.4 -- and no sleep after the final attempt.
    assert sleeps == [pytest.approx(0.2), pytest.approx(0.4)], "backoff schedule changed"


def test_resolution_failure_still_fails_closed_through_the_offload(monkeypatch):
    """A resolver error inside the threaded call is still swallowed by scope_guard into
    "out of scope" -- it does not propagate out of `to_thread` and fail the scan."""
    def _boom(host, *args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "deterministic stub")
    monkeypatch.setattr(net_guard, "resolve_hostname", _boom)
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)

    upstream_cls, _ = _runner(
        "httpx", 20, _ok(), findings=[CommonFinding(asset_type="ip", value="203.0.113.5")]
    )
    downstream_cls, captured = _runner("nuclei", 50, _ok())
    outcome = asyncio.run(executor_mod.execute_leased_job(
        _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
        registry={"httpx": upstream_cls, "nuclei": downstream_cls},
    ))
    assert outcome == "completed"          # the scan is NOT failed by a DNS failure
    assert captured["prior_findings"] == []  # but the unresolvable host is not probed


# =========================================================================================
# 6. Existing exception behavior is preserved across the offload boundary.
# =========================================================================================

def test_unexpected_scope_guard_exception_still_propagates(monkeypatch):
    """`partition_in_scope` raising a non-resolver error must surface exactly as before --
    `to_thread` re-raises in the awaiting coroutine, so the executor's own error handling
    is reached unchanged. It must NOT be silently swallowed into an empty scope."""
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)

    class _Boom(RuntimeError):
        pass

    def _raise(*args, **kwargs):
        raise _Boom("scope guard exploded")

    monkeypatch.setattr(scope_guard, "partition_in_scope", _raise)

    upstream_cls, _ = _runner(
        "httpx", 20, _ok(),
        findings=[CommonFinding(asset_type="subdomain", value="sub.t.example.com")],
    )
    downstream_cls, _captured = _runner("nuclei", 50, _ok())

    with pytest.raises(_Boom):
        asyncio.run(executor_mod.execute_leased_job(
            _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
            registry={"httpx": upstream_cls, "nuclei": downstream_cls},
        ))


def test_net_policy_contextvar_survives_the_thread_offload(monkeypatch):
    """`asyncio.to_thread` copies the current context, so the scan's bound net_policy is
    still visible inside the resolver. Without this, a PRIVATE scan's split-horizon DNS
    would silently fall back to the public resolver on the worker path -- a leak."""
    from apps.api.scanner_engine import net_policy

    seen: list = []

    def _resolve(host, *args, **kwargs):
        seen.append(net_policy.current())
        raise socket.gaierror(socket.EAI_NONAME, "deterministic stub")

    monkeypatch.setattr(net_guard, "resolve_hostname", _resolve)
    monkeypatch.setattr(get_settings(), "scan_enforce_derived_scope", True)

    sentinel = object()
    upstream_cls, _ = _runner(
        "httpx", 20, _ok(), findings=[CommonFinding(asset_type="ip", value="203.0.113.11")]
    )
    downstream_cls, _c = _runner("nuclei", 50, _ok())

    async def _scenario():
        token = net_policy.set_policy(sentinel)
        try:
            return await executor_mod.execute_leased_job(
                _job(modules=("httpx", "nuclei")), policy=None, reporter=None,
                registry={"httpx": upstream_cls, "nuclei": downstream_cls},
            )
        finally:
            net_policy.reset_policy(token)

    asyncio.run(_scenario())
    assert seen, "resolver was never reached"
    assert all(p is sentinel for p in seen), (
        "the bound net_policy did not reach the offloaded thread"
    )
