"""Worker-side lease loop -- the execution plane's replacement for Celery consumption.

WHY THIS EXISTS
---------------
A `celery worker` must connect to Redis to consume tasks. Once the scanner was removed
from `mbs-core` (MBS.SC Property A), Redis became unreachable by design, so the isolated
worker could no longer receive work at all. This module is the replacement: instead of the
worker reaching INTO the control plane for a task, it asks the scanner-manager for one and
is handed an already-authorized execution plan.

    Celery model (control plane)        Lease model (execution plane)
    ---------------------------         -----------------------------
    worker -> Redis (broker)            worker -> manager /v1/lease   (HTTP, mbs-dispatch)
    worker -> MySQL (read scan)         manager hands over the plan
    worker -> MySQL/MinIO (write)       worker -> manager /v1/tool-results, /v1/evidence
    fencing: execution_token            fencing: THE SAME execution_token

The fencing is deliberately identical, not merely analogous: `/v1/lease` claims through
`orchestrator._claim_scan` and `/v1/lease/complete` finalises through
`orchestrator._finalize_status`, so a lease-model worker and a (control-plane) Celery
executor contend on ONE mechanism. Two mechanisms could disagree about who owns a scan;
one cannot.

WHAT THIS MODULE MAY NOT DO
---------------------------
No database session, no Redis client, no object-store client, no API call. If something
here ever needs one, the correct fix is a new narrowly-scoped manager endpoint -- not a
credential. `enforce_execution_plane_credentials` fails the process at startup if a
control-plane credential is present, so a regression here is loud rather than silent.

TRUST MODEL FOR A LEASED JOB
----------------------------
The manager is authoritative, but the worker still re-validates every job it receives
before executing it. That is not redundancy for its own sake: a job arrives over the
network, and "it was handed to me" is not the same as "it is authorized for me". The
worker checks the job against its OWN configured identity (from its environment, which the
manager cannot influence) and fails closed on any mismatch. A manager that was compromised,
misconfigured, or impersonated therefore still cannot make this worker scan another
tenant's network.
"""
from __future__ import annotations

import asyncio
import inspect
import logging
import random
import signal
import uuid
from dataclasses import dataclass, field

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_policy
from apps.api.scanner_engine.scan_routing import JobNotForThisWorker, assert_job_matches_worker

logger = logging.getLogger(__name__)


def _now() -> float:
    """Monotonic clock for beat pacing. Deliberately not wall time: an NTP step backwards
    would otherwise stall heartbeats until the clock caught up."""
    import time

    return time.monotonic()


def _max_handshake_age_s() -> int:
    """The configured stale-handshake threshold, or the module default.

    Read through `get_settings()` so the health REPORT and the per-job GATE use one
    number: a metric that called a tunnel healthy while the gate was refusing jobs on it
    (or the reverse) would be worse than no metric at all. Falls back to the wireguard
    module's own default if the setting is absent, never to an unbounded value."""
    from apps.api.scanner_engine.wireguard import DEFAULT_MAX_HANDSHAKE_AGE_S

    try:
        value = getattr(get_settings(), "scanner_wireguard_max_handshake_age_s", None)
    except Exception:  # noqa: BLE001 -- settings must never break liveness reporting
        return DEFAULT_MAX_HANDSHAKE_AGE_S
    return int(value) if value else DEFAULT_MAX_HANDSHAKE_AGE_S


class LeaseError(RuntimeError):
    """A lease could not be obtained or completed. `reason` is a stable code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


# Stable refusal reasons. These are the worker-side vocabulary; they intentionally mirror
# the manager's codes so an operator reading either side sees the same word.
REASON_WORKER_UNAUTHORIZED = "WORKER_UNAUTHORIZED"
REASON_POOL_MISMATCH = "POOL_MISMATCH"
REASON_SITE_MISMATCH = "SITE_MISMATCH"
REASON_WORKSPACE_MISMATCH = "WORKSPACE_MISMATCH"
REASON_EXECUTION_TOKEN_INVALID = "EXECUTION_TOKEN_INVALID"
REASON_CIDR_NOT_AUTHORIZED = "CIDR_NOT_AUTHORIZED"
REASON_TUNNEL_UNHEALTHY = "TUNNEL_UNHEALTHY"
REASON_MANAGER_UNAVAILABLE = "MANAGER_UNAVAILABLE"
REASON_AUTH_FAILED = "WORKER_AUTH_FAILED"
REASON_MISSING_TARGET = "JOB_MISSING_TARGET"
# A 4xx that is NOT 401/403: the manager understood the request and REFUSED it on its
# merits (e.g. a terminal status this manager build does not accept). Retrying replays a
# byte-identical body to a deterministic validator, so every attempt fails identically --
# the request itself must change, and only a deploy or a code fix can change it. Kept
# distinct from REASON_AUTH_FAILED so an operator can tell "this worker is not allowed"
# apart from "this request is not acceptable".
REASON_REQUEST_REJECTED = "MANAGER_REQUEST_REJECTED"
# Dedicated VPN egress. Distinct from the private-tunnel codes so an operator can tell the
# two tunnels apart in a log without cross-referencing anything.
REASON_EGRESS_UNHEALTHY = "VPN_EGRESS_UNHEALTHY"
REASON_EGRESS_MODE_MISMATCH = "EGRESS_MODE_MISMATCH"
REASON_EGRESS_LOST_MIDSCAN = "VPN_EGRESS_LOST_MIDSCAN"


@dataclass(frozen=True)
class WorkerIdentity:
    """Who this worker is, from ITS OWN configuration -- never from a leased job.

    This is the fixed point every job is checked against. It comes from the environment the
    container was started with, so a job payload cannot alter it.
    """

    worker_id: str
    pool_id: str
    site_id: str | None = None
    manager_url: str = ""
    token: str = ""
    # EXPLICIT egress mode: "direct" | "vpn". Declared, never inferred from the presence of
    # a key file -- a secret that failed to mount would otherwise silently downgrade a VPN
    # worker to a direct one, which is the exact failure this feature exists to prevent.
    egress_mode: str = "direct"

    @property
    def is_private(self) -> bool:
        return bool(self.site_id)

    @property
    def is_vpn_egress(self) -> bool:
        return (self.egress_mode or "direct").strip().lower() == "vpn"

    @classmethod
    def from_settings(cls, settings=None) -> "WorkerIdentity":
        s = settings or get_settings()
        return cls(
            worker_id=(s.scanner_worker_id or "").strip(),
            pool_id=(s.scanner_pool_id or "").strip(),
            site_id=(s.scanner_site_id or "").strip() or None,
            manager_url=(s.scanner_manager_url or "").strip(),
            token=(s.scanner_worker_token or "").strip(),
            egress_mode=(getattr(s, "scanner_egress_mode", "direct") or "direct").strip().lower(),
        )


@dataclass
class BackoffPolicy:
    """Bounded exponential backoff with jitter.

    Jitter matters more than the exponent here: a fleet of workers that all lost the
    manager at the same moment will otherwise retry in lockstep and arrive as a thundering
    herd exactly when the manager is least able to serve them. Full jitter (a uniform draw
    from [0, delay]) spreads them out.
    """

    base_seconds: float = 1.0
    max_seconds: float = 60.0
    # Sleep between successful polls that returned no work. Not zero: an idle worker
    # polling in a tight loop is a self-inflicted denial of service on the manager.
    idle_seconds: float = 5.0
    # How often a RUNNING job reports liveness. Must be comfortably shorter than
    # settings.scan_stale_heartbeat_seconds (which is ~30 beats wide) so a few missed beats
    # can never cause a false reap -- matching TOOL_PROGRESS_INTERVAL_SECONDS on the
    # Celery path, so both dispatch models produce the same liveness cadence.
    heartbeat_seconds: float = 30.0
    _attempt: int = field(default=0, repr=False)

    def reset(self) -> None:
        self._attempt = 0

    def next_delay(self) -> float:
        delay = min(self.max_seconds, self.base_seconds * (2 ** self._attempt))
        self._attempt += 1
        return random.uniform(0, delay)


class ManagerClient:
    """Minimal HTTP client for the manager boundary.

    Injectable transport so the loop is testable without a live manager, and so the real
    deployment can add mTLS without touching the loop. It holds the worker's own token and
    nothing else -- there is no credential here for any control-plane service.
    """

    def __init__(self, identity: WorkerIdentity, *, transport=None, timeout: float = 30.0) -> None:
        self.identity = identity
        self._transport = transport
        self._timeout = timeout

    def _headers(self) -> dict:
        return {
            "X-Worker-Id": self.identity.worker_id,
            "Authorization": f"Bearer {self.identity.token}",
        }

    async def _request(self, method: str, path: str, *, json=None) -> dict:
        url = f"{self.identity.manager_url.rstrip('/')}{path}"
        if self._transport is not None:
            return await self._transport(method, url, headers=self._headers(), json=json)
        import httpx

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.request(method, url, headers=self._headers(), json=json)
            if resp.status_code in (401, 403):
                # An auth/authorization refusal is NOT retryable: retrying a revoked
                # credential just hammers the manager with requests that can never succeed.
                raise LeaseError(
                    REASON_AUTH_FAILED,
                    f"manager refused this worker ({resp.status_code}): "
                    f"{resp.text[:200]}",
                )
            if 400 <= resp.status_code < 500:
                # PERMANENT. A 4xx here means the manager parsed this request and rejected
                # its CONTENT -- the exact same bytes will be rejected the same way on every
                # retry, so retrying only delays the failure and hides it behind backoff.
                # The body is included because it carries the manager's own refusal code
                # (INVALID_TERMINAL_STATUS and friends), which is the one piece of
                # information that says WHY, and without it this is indistinguishable in a
                # log from a transport fault.
                raise LeaseError(
                    REASON_REQUEST_REJECTED,
                    f"manager rejected this request ({resp.status_code}) at {path}: "
                    f"{resp.text[:500]}",
                )
            resp.raise_for_status()
            return resp.json()

    async def heartbeat(self, *, health_state: str = "healthy", detail=None,
                        handshake_age_s=None, scan_id=None, execution_token=None) -> dict:
        """Worker liveness, and -- while a job is running -- SCAN liveness too.

        `scan_id` + `execution_token` are sent together or not at all: the manager stamps
        `scans.last_heartbeat_at` through the same fenced UPDATE the Celery executor uses,
        so naming a scan without owning its token refreshes nothing.
        """
        body = {
            "health_state": health_state, "detail": detail,
            "handshake_age_s": handshake_age_s,
        }
        if scan_id is not None and execution_token is not None:
            body["scan_id"] = str(scan_id)
            body["execution_token"] = str(execution_token)
        return await self._request("POST", "/v1/heartbeat", json=body)

    async def site_config(self) -> dict:
        """This worker's OWN site configuration, for tunnel bring-up.

        Takes no site parameter by design -- the manager reads the site from this worker's
        row, so there is no request shape in which a worker can ask for another customer's
        tunnel configuration. The response carries PUBLIC key material only; the worker's
        own private key never leaves this container.
        """
        return await self._request("GET", "/v1/site-config")

    async def lease(self, max_jobs: int = 1) -> list:
        body = await self._request("POST", "/v1/lease", json={"max_jobs": max_jobs})
        return list(body.get("jobs") or [])

    async def scan_status(self, *, scan_id, execution_token) -> str | None:
        """Why this execution should stop, or None to keep going. The CANCELLATION PROBE.

        A read-only question to the manager, which answers it from the same
        `_execution_stop_reason` the Celery executor calls directly. This worker has no
        database, so the manager boundary is the only place the question can be asked.

        Returns the raw reason ('cancelled' / 'revoked') or None. It does NOT swallow
        errors: the CALLER decides what a failed probe means, and the executor's rule is
        fail-open (see `execute_leased_job`). Swallowing here would hide a manager outage
        from the logs while silently producing the same answer as a healthy scan.
        """
        body = await self._request(
            "GET",
            f"/v1/scan-status?scan_id={scan_id}&execution_token={execution_token}",
        )
        reason = body.get("stop_reason")
        return str(reason) if reason else None

    async def complete(self, *, scan_id, execution_token, status: str, reason=None) -> dict:
        return await self._request("POST", "/v1/lease/complete", json={
            "scan_id": str(scan_id), "execution_token": str(execution_token),
            "status": status, "reason": reason,
        })


def validate_leased_job(job: dict, identity: WorkerIdentity) -> None:
    """Re-validate a leased job against THIS worker's own identity. Fail closed.

    The manager already authorized the job; this is the worker refusing to take anything
    on trust. Every check compares a field of the JOB against a field of the IDENTITY, and
    the identity came from the environment, so a hostile or broken manager cannot satisfy
    these by construction.
    """
    if not job.get("scan_id"):
        raise LeaseError(REASON_MISSING_TARGET, "leased job carries no scan_id")

    token = job.get("execution_token")
    if not token:
        raise LeaseError(
            REASON_EXECUTION_TOKEN_INVALID,
            "leased job carries no execution token; refusing to run unfenced work",
        )
    try:
        uuid.UUID(str(token))
    except (ValueError, TypeError):
        raise LeaseError(
            REASON_EXECUTION_TOKEN_INVALID, f"execution token {token!r} is not a valid UUID"
        )

    zone = job.get("network_zone") or "public"
    job_site = job.get("site_id")

    # Zone/site binding, in both directions -- a public worker must never take private
    # work (it has no tunnel), and a private worker must never take public work (a machine
    # holding a customer's tunnel must not also be reaching arbitrary internet hosts).
    try:
        assert_job_matches_worker(
            job_network_zone=zone,
            job_site_id=job_site,
            worker_site_id=identity.site_id,
            worker_pool_id=identity.pool_id,
            job_pool_id=job.get("pool_id"),
        )
    except JobNotForThisWorker as exc:
        mapped = {
            "WORKER_WRONG_SITE": REASON_SITE_MISMATCH,
            "WORKER_WRONG_POOL": REASON_POOL_MISMATCH,
        }.get(exc.reason, REASON_WORKER_UNAUTHORIZED)
        raise LeaseError(mapped, exc.message) from exc

    if zone == "private":
        # A private job with no authorized CIDRs cannot be executed safely: there would be
        # nothing to constrain the scan to, and an empty list must never read as
        # "unrestricted".
        if not (job.get("authorized_cidrs") or []):
            raise LeaseError(
                REASON_CIDR_NOT_AUTHORIZED,
                "private job carries no authorized CIDRs; refusing to scan an "
                "unconstrained private range",
            )

    # EGRESS MODE, re-checked worker-side against our OWN configuration.
    #
    # The manager already refuses to lease a vpn-required job to a direct worker. This is
    # the worker's independent restatement of the same rule, and it exists for the reason
    # the module docstring gives: "it was handed to me" is not "it is authorized for me".
    # A compromised, misconfigured or impersonated manager still cannot make a DIRECT
    # worker run a scan that was required to leave via the VPN -- which would have run
    # from the platform's own address while the scan record claimed VPN egress.
    required_egress = (job.get("required_egress_mode") or "").strip().lower()
    if required_egress and required_egress != (identity.egress_mode or "direct").strip().lower():
        raise LeaseError(
            REASON_EGRESS_MODE_MISMATCH,
            f"job requires egress mode {required_egress!r} but this worker is "
            f"{identity.egress_mode!r}; refusing. Running it here would send target "
            f"traffic out a path the scan was not authorized to use.",
        )

    target = job.get("target") or {}
    if not target.get("value"):
        raise LeaseError(REASON_MISSING_TARGET, "leased job carries no target value")


def build_policy_for_job(job: dict) -> net_policy.ScanNetworkPolicy:
    """The per-scan network policy for a leased job.

    A public job gets PUBLIC-ONLY, which authorizes no private range whatever the global
    settings say. A private job gets exactly the CIDRs and resolvers the manager handed
    over -- which the manager derived from the site row it had just authorized.
    """
    workspace_id = job.get("workspace_id")
    scan_id = job.get("scan_id")
    ws = uuid.UUID(str(workspace_id)) if workspace_id else None
    sid = uuid.UUID(str(scan_id)) if scan_id else None

    if (job.get("network_zone") or "public") != "private":
        return net_policy.build_public_policy(workspace_id=ws, scan_id=sid)

    return net_policy.build_private_policy(
        workspace_id=ws,
        scan_id=sid,
        site_id=uuid.UUID(str(job["site_id"])),
        authorized_cidrs=job.get("authorized_cidrs") or [],
        dns_servers=job.get("dns_servers") or [],
        worker_id=job.get("worker_id"),
        pool_id=job.get("pool_id"),
    )


def preflight_private_job(job: dict, *, probe=None) -> None:
    """Tunnel health gate for a private job (Phase 12). No probe -> no private scanning.

    A missing probe is a REFUSAL, not a pass: without one we cannot show the tunnel is up,
    and starting a scan we cannot route is how "no findings" becomes indistinguishable from
    "never reached the network".
    """
    if (job.get("network_zone") or "public") != "private":
        return
    from apps.api.scanner_engine import wireguard

    if probe is None:
        raise LeaseError(
            REASON_TUNNEL_UNHEALTHY,
            "no tunnel probe configured on this worker; refusing to start a private scan "
            "whose tunnel health cannot be established",
        )
    try:
        wireguard.preflight(
            site_id=job.get("site_id"),
            authorized_cidrs=job.get("authorized_cidrs") or [],
            probe=probe,
        )
    except wireguard.TunnelUnhealthy as exc:
        # Surface the SPECIFIC reason (ROUTE_MISSING / HANDSHAKE_STALE / ...) rather than a
        # generic failure, so an operator knows which thing to fix.
        raise LeaseError(exc.reason, exc.message) from exc
    except wireguard.WireGuardConfigError as exc:
        # O-1. The job's OWN `authorized_cidrs` are unusable -- malformed, empty after
        # parsing, or a default route (`build_allowed_ips` refuses 0.0.0.0/0 outright).
        # That is a property of the LEASED JOB, so it belongs on the job-rejection path
        # next to the `authorized_cidrs`-empty check in `validate_leased_job`.
        #
        # Without this the exception escaped `_handle_job`'s `except LeaseError` and was
        # caught by `run()`'s transport handler, which logged `manager_unavailable` and
        # backed off: the scan was never handed back as failed, `stats["rejected"]` stayed
        # 0, and a forged/broken job read as a network problem. Execution was still
        # refused -- this changes only how the refusal is classified and reported.
        #
        # Caught NARROWLY and translated, never swallowed: WireGuardConfigError is a
        # ValueError raised solely by this module's own config/CIDR validation, so it
        # cannot mask a transport failure or a programming error, both of which keep their
        # existing paths.
        raise LeaseError(REASON_CIDR_NOT_AUTHORIZED, str(exc)) from exc


def preflight_egress_job(
    job: dict, *, identity: WorkerIdentity, probe=None, settings=None
) -> None:
    """VPN egress health gate for a job on a VPN-egress worker. No probe -> no scanning.

    Deliberately mirrors `preflight_private_job`'s shape and fail-closed stance, against a
    different failure: there, an unhealthy tunnel means a scan that never reaches the
    network and reports "clean"; here, it means a scan that DOES reach the network but
    from the platform's own address, leaking our infrastructure to the target and breaking
    the attribution the customer was promised.

    A missing probe is a REFUSAL, not a pass. Without one we cannot show target traffic is
    on the VPN, and "probably still tunnelled" is not a basis for scanning.
    """
    if not identity.is_vpn_egress:
        return  # a direct worker has no VPN path to verify
    from apps.api.scanner_engine import vpn_egress

    if probe is None:
        raise LeaseError(
            REASON_EGRESS_UNHEALTHY,
            "no VPN egress probe configured on this worker; refusing to start a scan whose "
            "egress path cannot be established",
        )
    s = settings or get_settings()
    try:
        vpn_egress.preflight(
            probe=probe,
            expected_exit_ip=(s.scanner_vpn_egress_expected_exit_ip or None),
            forbidden_exit_ips=s.vpn_egress_forbidden_exit_ip_list,
            max_handshake_age_s=s.scanner_vpn_egress_max_handshake_age_s,
        )
    except vpn_egress.EgressUnhealthy as exc:
        # Surface the SPECIFIC reason (EXIT_IP_MISMATCH / ROUTE_MISSING / ...) rather than
        # a generic failure, so an operator knows which thing to fix.
        try:
            from apps.api.core.observability import record_vpn_egress_blocked

            record_vpn_egress_blocked(exc.reason)
        except Exception:  # noqa: BLE001 -- metrics must never mask the refusal
            pass
        raise LeaseError(exc.reason, exc.message) from exc
    except vpn_egress.VpnEgressConfigError as exc:
        # The worker's own egress configuration is unusable. Classified as a job rejection
        # for the same reason O-1 reclassified WireGuardConfigError: otherwise it escapes
        # `_handle_job`'s handler, is caught by the transport handler in `run()`, and a
        # configuration fault is reported as `manager_unavailable` with the scan left
        # unreported.
        raise LeaseError(REASON_EGRESS_UNHEALTHY, str(exc)) from exc


def _accepts_stop_probe(executor) -> bool:
    """Does this executor accept the `stop_probe` keyword? Fail-safe: False on doubt.

    A callable whose signature cannot be read (a C builtin, an exotic wrapper) is treated
    as NOT supporting it, so the worst case is the pre-Phase-1 behaviour -- a scan that
    runs to completion without the cancellation probe -- rather than a TypeError that
    would fail a perfectly good scan.
    """
    try:
        params = inspect.signature(executor).parameters
    except (TypeError, ValueError):
        return False
    if "stop_probe" in params:
        return True
    return any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


class LeaseLoop:
    """Poll the manager for work, execute it, report the outcome, repeat.

    `executor` is injected: it takes (job, policy) and returns a terminal status string.
    Injecting it keeps this module free of the scanner pipeline's imports (so it stays
    testable without tools installed) and lets the real deployment supply the pipeline.
    """

    def __init__(
        self,
        identity: WorkerIdentity,
        client: ManagerClient,
        *,
        executor=None,
        backoff: BackoffPolicy | None = None,
        tunnel_probe=None,
        egress_probe=None,
        max_iterations: int | None = None,
    ) -> None:
        self.identity = identity
        self.client = client
        self.executor = executor
        self.backoff = backoff or BackoffPolicy()
        self.tunnel_probe = tunnel_probe
        # The VPN-egress probe, for a vpn-mode worker only. None on a direct worker, which
        # `preflight_egress_job` treats as "nothing to verify" -- and on a VPN worker,
        # None is a refusal rather than a pass.
        self.egress_probe = egress_probe
        # Bounds the loop in tests. None = run until stopped, which is the production case.
        self.max_iterations = max_iterations
        self._stopping = False
        # Set while a scan is executing, so shutdown can wait for it rather than
        # abandoning a half-finished scan.
        self._in_flight: dict | None = None
        self.stats = {"leased": 0, "completed": 0, "failed": 0, "rejected": 0, "idle": 0}
        # Set ONLY when the loop stops because this worker's IDENTITY was refused
        # (revoked / suspended / unknown credential) -- a condition no retry can clear.
        # None means the loop stopped for any survivable reason: a requested shutdown, or
        # `max_iterations` in tests. `main()` reads this to choose the process exit code,
        # so a permanently-unauthorized worker exits non-zero instead of looking like a
        # clean shutdown. Deliberately NOT set for a transient transport failure: those are
        # retried with backoff and never terminate the loop at all.
        self.fatal_reason: str | None = None

    # -- shutdown ----------------------------------------------------------------------

    def request_stop(self) -> None:
        """Stop requesting NEW work. In-flight work is allowed to finish.

        Deliberately cooperative: killing a running scan mid-flight would lose the partial
        output the tool has already produced, which `run_with_timeout` exists to preserve.
        """
        self._stopping = True

    def install_signal_handlers(self, loop=None) -> None:
        """SIGTERM/SIGINT -> stop leasing, drain, exit. No privileged behaviour."""
        loop = loop or asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.request_stop)
            except (NotImplementedError, RuntimeError):
                # Windows/proactor and non-main threads do not support this; the loop is
                # still stoppable via request_stop().
                logger.debug("lease_loop.signal_handler_unavailable sig=%s", sig)

    # -- one job -----------------------------------------------------------------------

    async def _handle_job(self, job: dict) -> None:
        scan_id = job.get("scan_id")
        token = job.get("execution_token")

        # 1. RE-VALIDATE against our own identity, before anything runs.
        try:
            validate_leased_job(job, self.identity)
            preflight_private_job(job, probe=self.tunnel_probe)
            preflight_egress_job(job, identity=self.identity, probe=self.egress_probe)
        except LeaseError as exc:
            self.stats["rejected"] += 1
            logger.warning(
                "lease_loop.job_rejected scan=%s reason=%s detail=%s",
                scan_id, exc.reason, exc.message,
                extra={"event": "lease_loop.job_rejected", "scan_id": str(scan_id),
                       "reason": exc.reason, "worker_id": self.identity.worker_id},
            )
            # Hand the scan back as FAILED with the reason, so it does not sit 'running'
            # until the orphan reaper notices. Best-effort: if the manager is unreachable
            # the reaper is the backstop, which is exactly its job.
            await self._safe_complete(scan_id, token, "failed", exc.reason)
            return

        # 2. EXECUTE inside the per-scan network policy. Everything downstream --
        #    net_guard, egress_guard, site DNS -- reads this contextvar, so the scan
        #    physically cannot reach outside its authorized set.
        policy = build_policy_for_job(job)
        status = "failed"
        reason = None
        # LIVENESS while the scan runs. Without this a leased scan never stamps
        # `scans.last_heartbeat_at`, so the orphan reaper cannot tell a healthy long scan
        # from a dead worker and falls back to its cruder runtime rule -- reaping healthy
        # long scans early and recovering dead ones late. The beat is cancelled in the
        # `finally` below, so the instant this worker dies the stamps stop and the reaper
        # sees the silence. That is precisely how an abandoned lease is detected.
        beat = asyncio.ensure_future(self._heartbeat_while_running(scan_id, token))
        # MID-SCAN EGRESS WATCHDOG. Per-job preflight gates the START of a scan; it says
        # nothing about the next 40 minutes. If the VPN drops while nuclei is running, the
        # kill-switch stops the packets at the kernel (tools start failing) -- but the SCAN
        # would otherwise carry on and report its partial results as a completed scan. This
        # task re-verifies the path on an interval and CANCELS the execution the moment it
        # cannot prove egress is still on the VPN, so the scan fails loudly instead of
        # silently becoming a partial one. Direct workers get no watchdog (nothing to lose).
        watchdog = None
        exec_task = None
        try:
            with net_policy.bind(policy):
                if self.executor is None:
                    raise LeaseError(
                        "NO_EXECUTOR", "no executor configured on this lease loop"
                    )
                # COOPERATIVE CANCELLATION (Phase 1). The executor is handed a probe it
                # can call between tools to ask the manager whether this scan is still
                # ours to run.
                #
                # Passed only to an executor that actually accepts it. `executor` is an
                # injected callable -- `build_executor` in production, a plain two-argument
                # fake in most tests -- so widening its REQUIRED contract here would break
                # every existing caller. The support question is answered by inspecting the
                # signature BEFORE calling, deliberately: catching TypeError around the
                # call instead would be indistinguishable from a TypeError raised inside a
                # half-finished scan, and retrying that would run the tools a second time.
                if _accepts_stop_probe(self.executor):
                    coro = self.executor(
                        job, policy, stop_probe=self._stop_probe(scan_id, token)
                    )
                else:
                    coro = self.executor(job, policy)

                if self.identity.is_vpn_egress and self.egress_probe is not None:
                    # Race the scan against the watchdog. `ensure_future` on the executor
                    # coroutine is what makes the scan CANCELLABLE -- awaiting it directly
                    # would leave no handle to stop when the watchdog fires.
                    exec_task = asyncio.ensure_future(coro)
                    watchdog = asyncio.ensure_future(self._watch_egress_while_running())
                    done, _ = await asyncio.wait(
                        {exec_task, watchdog}, return_when=asyncio.FIRST_COMPLETED
                    )
                    if watchdog in done and not exec_task.done():
                        # Egress went unhealthy mid-scan. Cancel the execution and fail the
                        # scan: continuing would produce results gathered over an
                        # unverified path, which is worse than no results because it looks
                        # like a completed scan.
                        exec_task.cancel()
                        try:
                            await exec_task
                        except BaseException:  # noqa: BLE001 -- CancelledError expected
                            pass
                        # Named distinctly from the `except ... as exc` bindings below:
                        # reusing `exc` here assigns into the same function-local slot the
                        # handlers rebind, which type checkers reject outright.
                        watchdog_exc = watchdog.exception()
                        raise watchdog_exc if watchdog_exc is not None else LeaseError(
                            REASON_EGRESS_LOST_MIDSCAN,
                            "VPN egress became unverifiable while the scan was running",
                        )
                    status = await exec_task
                else:
                    status = await coro
        except LeaseError as exc:
            reason = exc.reason
            logger.warning("lease_loop.execution_refused scan=%s reason=%s", scan_id, exc.reason)
        except Exception as exc:  # noqa: BLE001 -- a tool failure must not kill the loop
            reason = type(exc).__name__
            logger.exception(
                "lease_loop.execution_failed scan=%s", scan_id,
                extra={"event": "lease_loop.execution_failed", "scan_id": str(scan_id)},
            )
        finally:
            # Stop the liveness beat and WAIT for it to actually finish. Awaiting the
            # cancelled task (rather than firing and forgetting) means no stray heartbeat
            # can land after the terminal write below -- which would briefly make a
            # finished scan look alive again.
            beat.cancel()
            try:
                await beat
            except BaseException:  # noqa: BLE001 -- CancelledError is expected here
                pass
            # Same discipline for the egress watchdog: cancel and AWAIT, so a pending
            # check cannot outlive the scan it was guarding and fire against the next one.
            if watchdog is not None:
                watchdog.cancel()
                try:
                    await watchdog
                except BaseException:  # noqa: BLE001 -- CancelledError expected
                    pass
            self._in_flight = None

        # 3. TERMINAL WRITE, fenced by the execution token.
        accepted = await self._safe_complete(scan_id, token, status, reason)
        if accepted and status in ("completed", "completed_with_errors"):
            self.stats["completed"] += 1
        elif status not in ("completed", "completed_with_errors"):
            self.stats["failed"] += 1

    # -- tunnel health reporting (PHASE 8 Tier 1) ---------------------------------------

    def observe_tunnel_health(self) -> tuple[str, int | None, str | None]:
        """(health_state, handshake_age_s, detail) for THIS worker, right now.

        PHASE 8 P8-A/P8-B. The control plane previously had no view of tunnel health at
        all: `ManagerClient.heartbeat` accepted `health_state`/`handshake_age_s`, but the
        only caller passed neither, so a private worker with a perfectly healthy tunnel sat
        in the database as `health_state='unknown', last_seen_at=NULL` -- and the
        `MbsPrivateTunnelDown` / `MbsTunnelHandshakeStale` alerts queried a metric nothing
        ever emitted. This is the single place that turns the probe into both.

        IT DOES NOT IMPLEMENT A SECOND HEALTH MODEL. The verdict comes from the SAME
        `probe.status()` + `wireguard.assert_tunnel_healthy()` pair that the per-job gate
        uses, with the same configured handshake threshold, so the number reported here and
        the decision to refuse a job can never disagree.

        REPORTING ONLY. Nothing here gates, authorizes, or refuses anything -- the Phase 7
        per-job fail-closed gate (`preflight_private_job`) is untouched and still runs
        independently. This function is therefore additive by construction: if it raised or
        returned nonsense, scans would still be refused exactly as before.

        Fails toward UNHEALTHY. A probe that cannot observe the tunnel (missing binary,
        permission error, timeout) yields `unhealthy`, never `healthy` -- a metric that
        reports healthy for a tunnel it cannot see is worse than no metric, because an
        operator would trust it.

        A PUBLIC worker has no tunnel and no probe: it reports `healthy` with no handshake
        age, which is the truthful statement for a worker that is not supposed to have one.
        """
        if not self.identity.is_private or self.tunnel_probe is None:
            return "healthy", None, None

        from apps.api.scanner_engine import wireguard

        try:
            status = self.tunnel_probe.status(self.identity.site_id)
        except Exception as exc:  # noqa: BLE001 -- an unobservable tunnel is unhealthy
            return "unhealthy", None, f"probe failed: {type(exc).__name__}"

        age = getattr(status, "last_handshake_age_s", None)
        # Judged against the routes the tunnel ACTUALLY carries, read from the SAME status
        # object -- one probe call, so the verdict cannot be split across two observations
        # of a tunnel that changed in between. This reporting path deliberately keeps no
        # copy of the site's authorized CIDRs: the per-job gate judges each job against the
        # AUTHORITATIVE list carried on the job itself, and that check is unchanged.
        routes = [str(r) for r in (getattr(status, "routes", None) or ())]
        if not routes:
            # No route at all. `assert_tunnel_healthy` cannot be asked this question with an
            # empty CIDR list (build_allowed_ips rejects it for a reason unrelated to the
            # tunnel), so the condition is reported directly -- but the MOST ACTIONABLE
            # cause wins, exactly as assert_tunnel_healthy orders its own checks: a down
            # interface has no routes BECAUSE it is down, and saying "ROUTE_MISSING" would
            # point an operator at the routing table instead of the interface.
            if not status.interface_up:
                return "unhealthy", age, wireguard.REASON_TUNNEL_UNHEALTHY
            if age is None:
                return "unhealthy", age, wireguard.REASON_NO_HANDSHAKE
            return "unhealthy", age, wireguard.REASON_ROUTE_MISSING
        try:
            wireguard.assert_tunnel_healthy(
                status,
                authorized_cidrs=routes,
                max_handshake_age_s=_max_handshake_age_s(),
            )
        except wireguard.TunnelUnhealthy as exc:
            return "unhealthy", age, exc.reason
        except Exception as exc:  # noqa: BLE001 -- never let reporting raise into the loop
            return "unhealthy", age, f"health check failed: {type(exc).__name__}"
        return "healthy", age, None

    def health_payload(self) -> dict:
        """The heartbeat body for THIS worker's current observed health.

        Exists so a caller outside the loop (`main._announce_liveness`, which heartbeats
        once before private tunnel setup) sends exactly what `report_health` would send,
        rather than assembling a second, drift-prone payload. Reports what
        `observe_tunnel_health()` actually observed -- `unhealthy` for a private worker
        whose tunnel is not up yet -- so a pre-tunnel heartbeat never overstates readiness.

        Deliberately does NOT send or emit anything: it is a pure projection, so the caller
        decides whether a failure is fatal. `report_health` keeps swallowing errors (a
        heartbeat must never break a running scan); the startup caller does not, because a
        refused credential at startup is exactly what it needs to surface.
        """
        state, age, detail = self.observe_tunnel_health()
        return {"health_state": state, "detail": detail, "handshake_age_s": age}

    async def report_health(self, *, scan_id=None, execution_token=None) -> None:
        """Send one heartbeat carrying tunnel health, and emit the tunnel metrics.

        BEST-EFFORT by design (see `_heartbeat_while_running`): liveness reporting must
        never be able to fail a scan or stop the lease loop, so every error is swallowed.
        The metric is recorded BEFORE the network call, so a manager outage still leaves a
        local metric an operator can scrape.
        """
        state, age, detail = self.observe_tunnel_health()

        # P8-A: this is the call site `record_tunnel_state` never had. Private workers only
        # -- a public worker has no tunnel, and emitting `up=1` for it would make the
        # tunnel-down alert meaningless by diluting it with pools that have no tunnel.
        if self.identity.is_private:
            try:
                from apps.api.core.observability import record_tunnel_state

                record_tunnel_state(
                    self.identity.pool_id, up=(state == "healthy"), handshake_age_s=age
                )
            except Exception as exc:  # noqa: BLE001 -- metrics must never break the worker
                logger.debug("lease_loop.metric_failed error=%s", exc)

        try:
            await self.client.heartbeat(
                health_state=state, detail=detail, handshake_age_s=age,
                scan_id=scan_id, execution_token=execution_token,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 -- liveness must not break the scan
            logger.debug(
                "lease_loop.heartbeat_failed scan=%s error=%s", scan_id, exc,
                extra={"event": "lease_loop.heartbeat_failed",
                       "scan_id": str(scan_id) if scan_id else None},
            )

    async def _heartbeat_while_running(self, scan_id, token) -> None:
        """Refresh this scan's liveness until cancelled.

        BEST-EFFORT, exactly like the Celery path's `_stamp_heartbeat`: a failed or slow
        heartbeat must never fail a scan that is otherwise running fine, so every error is
        swallowed and the beat simply tries again. Missing a few beats is harmless --
        `scan_stale_heartbeat_seconds` is many beats wide precisely so a transient blip
        cannot cause a false reap.

        PHASE 8: the beat now carries tunnel health as well as scan liveness. Same cadence
        (`backoff.heartbeat_seconds`, unchanged at 30s), same fenced scan update -- the
        health fields ride along on a call that was already being made.
        """
        while True:
            try:
                await asyncio.sleep(self.backoff.heartbeat_seconds)
                await self.report_health(scan_id=scan_id, execution_token=token)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- liveness must not break the scan
                logger.debug(
                    "lease_loop.heartbeat_failed scan=%s error=%s", scan_id, exc,
                    extra={"event": "lease_loop.heartbeat_failed", "scan_id": str(scan_id)},
                )

    async def _watch_egress_while_running(self) -> None:
        """Re-verify VPN egress on an interval; RAISE the moment it cannot be proven.

        DELIBERATELY NOT BEST-EFFORT -- and that is the one place this differs from
        `_heartbeat_while_running` above, which swallows everything. The difference is what
        each one protects:

          * a missed HEARTBEAT costs liveness reporting. Failing a healthy scan over it
            would be a self-inflicted outage, so it is swallowed.
          * a missed EGRESS CHECK means we can no longer show target traffic is on the VPN.
            Continuing would produce a scan whose traffic may have left from the
            platform's own address -- reported as a successful scan. Failing loudly is
            strictly better than a result nobody can trust.

        So an unhealthy observation, an unreadable probe, and an exception inside the probe
        all end the same way: raise, which cancels the scan. Unknown is never "fine".

        Returns only if cancelled (the normal end, when the scan finishes first).
        """
        from apps.api.scanner_engine import vpn_egress

        settings = get_settings()
        interval = max(
            5, int(getattr(settings, "scanner_vpn_egress_recheck_seconds", 60) or 60)
        )
        while True:
            await asyncio.sleep(interval)
            # Force a FRESH exit-IP observation rather than accepting the probe's cache:
            # a cached reading taken before the tunnel dropped is exactly the evidence
            # that would hide the drop.
            invalidate = getattr(self.egress_probe, "invalidate_exit_ip", None)
            if callable(invalidate):
                invalidate()
            try:
                vpn_egress.preflight(
                    probe=self.egress_probe,
                    expected_exit_ip=(settings.scanner_vpn_egress_expected_exit_ip or None),
                    forbidden_exit_ips=settings.vpn_egress_forbidden_exit_ip_list,
                    max_handshake_age_s=settings.scanner_vpn_egress_max_handshake_age_s,
                )
            except asyncio.CancelledError:
                raise
            except vpn_egress.EgressUnhealthy as exc:
                logger.error(
                    "lease_loop.egress_lost_midscan reason=%s detail=%s", exc.reason,
                    exc.message,
                    extra={"event": "lease_loop.egress_lost_midscan", "reason": exc.reason},
                )
                try:
                    from apps.api.core.observability import record_vpn_egress_midscan_loss

                    record_vpn_egress_midscan_loss(exc.reason)
                except Exception:  # noqa: BLE001 -- metrics must never mask the refusal
                    pass
                raise LeaseError(REASON_EGRESS_LOST_MIDSCAN, exc.message) from exc
            except Exception as exc:  # noqa: BLE001 -- unknown is NOT healthy
                logger.error(
                    "lease_loop.egress_check_failed error=%s", type(exc).__name__,
                    extra={"event": "lease_loop.egress_check_failed"},
                )
                raise LeaseError(
                    REASON_EGRESS_LOST_MIDSCAN,
                    f"VPN egress could not be verified mid-scan ({type(exc).__name__}); "
                    f"refusing to continue over an unverified path",
                ) from exc

    def _stop_probe(self, scan_id, execution_token):
        """A zero-argument coroutine the executor can await between tools.

        Binds this scan and this execution token to `ManagerClient.scan_status` so the
        executor never has to know the manager's wire shape -- it only asks "should I
        stop?". Raising is intentional and is part of the contract: the executor treats a
        failed probe as fail-open, and it can only do that if it can see the failure.
        """
        async def _probe() -> str | None:
            return await self.client.scan_status(
                scan_id=scan_id, execution_token=execution_token
            )

        return _probe

    async def _safe_complete(self, scan_id, token, status: str, reason) -> bool:
        """Report the terminal state, retrying a TRANSIENT manager outage.

        Never converts a failure into a success: if the manager will not accept the write,
        the scan is left for the orphan reaper rather than being reported complete. And an
        `accepted: false` response (our lease was superseded) is NOT retried -- someone
        else owns the row now, and retrying would be trying to overwrite them.
        """
        attempts = 3
        for attempt in range(attempts):
            try:
                result = await self.client.complete(
                    scan_id=scan_id, execution_token=token, status=status, reason=reason
                )
            except LeaseError as exc:
                if exc.reason == REASON_AUTH_FAILED:
                    logger.error(
                        "lease_loop.complete_unauthorized scan=%s -- credential refused; "
                        "leaving the scan for the orphan reaper", scan_id,
                    )
                    return False
                if exc.reason == REASON_REQUEST_REJECTED:
                    # PERMANENT: the manager rejected the terminal write itself, not the
                    # worker. The classic case is version skew -- a manager build older
                    # than this worker refusing a terminal status it does not know
                    # ('completed_with_errors'), which every retry re-sends unchanged.
                    # Retrying that spends the whole budget and then reports the same
                    # failure three attempts later, so we stop on the first one and say
                    # exactly what the manager said. The scan is left 'running' for the
                    # orphan reaper, as with any other refused terminal write: this method
                    # never converts a failure into a success.
                    logger.error(
                        "lease_loop.complete_rejected scan=%s status=%s -- manager refused "
                        "the terminal write (permanent, not retried): %s",
                        scan_id, status, exc.message,
                        extra={"event": "lease_loop.complete_rejected",
                               "scan_id": str(scan_id), "status": status,
                               "reason": exc.reason, "detail": exc.message},
                    )
                    return False
                raise
            except Exception as exc:  # noqa: BLE001 -- transport failure
                if attempt == attempts - 1:
                    logger.error(
                        "lease_loop.complete_unreachable scan=%s error=%s -- NOT marking "
                        "this scan successful; the orphan reaper will recover it",
                        scan_id, exc,
                        extra={"event": "lease_loop.complete_unreachable",
                               "scan_id": str(scan_id)},
                    )
                    return False
                await asyncio.sleep(self.backoff.next_delay())
                continue

            if not result.get("accepted", False):
                # Superseded: requeued on shutdown, reclaimed after a reap, or cancelled.
                logger.info(
                    "lease_loop.complete_superseded scan=%s reason=%s -- this execution is "
                    "no longer authoritative",
                    scan_id, result.get("reason"),
                    extra={"event": "lease_loop.complete_superseded",
                           "scan_id": str(scan_id), "reason": result.get("reason")},
                )
                return False
            self.backoff.reset()
            return True
        return False

    # -- the loop ----------------------------------------------------------------------

    async def run_once(self) -> int:
        """One poll. Returns how many jobs were handled (0 == idle)."""
        jobs = await self.client.lease(max_jobs=1)
        if not jobs:
            self.stats["idle"] += 1
            return 0
        self.stats["leased"] += len(jobs)
        for job in jobs:
            self._in_flight = job
            await self._handle_job(job)
        return len(jobs)

    async def run(self) -> dict:
        """Poll until stopped. Bounded backoff on failure; never a tight loop."""
        iterations = 0
        logger.info(
            "lease_loop.start worker=%s pool=%s site=%s manager=%s",
            self.identity.worker_id, self.identity.pool_id,
            self.identity.site_id or "-", self.identity.manager_url,
            extra={"event": "lease_loop.start", "worker_id": self.identity.worker_id,
                   "pool_id": self.identity.pool_id},
        )
        # PHASE 8 P8-B: report health once at startup, so a worker that comes up and then
        # sits idle is visible IMMEDIATELY rather than after the first beat interval. This
        # is what makes `last_seen_at` stop being NULL for an idle private worker.
        await self.report_health()
        # Monotonic so a clock adjustment cannot suppress or spam beats.
        last_beat = _now()
        while not self._stopping:
            if self.max_iterations is not None and iterations >= self.max_iterations:
                break
            iterations += 1
            try:
                handled = await self.run_once()
            except LeaseError as exc:
                if exc.reason == REASON_AUTH_FAILED:
                    # Revoked/suspended/unknown worker. Retrying cannot help and would
                    # only hammer the manager, so stop -- the container restarts and, if
                    # the credential is still dead, fails again visibly.
                    #
                    # RECORDED, not just logged. `run()` returns stats either way, so
                    # without this the caller cannot tell "stopped because its identity was
                    # refused" from "stopped cleanly on SIGTERM" -- and the process exited 0
                    # for both. Docker then showed `Restarting (0)`, an exit code that reads
                    # as a clean shutdown, while the worker was in fact permanently unable
                    # to work. Observed live for four days: 58 restarts, every one exit 0.
                    # `main()` maps this attribute to a non-zero exit (see main.py).
                    self.fatal_reason = exc.reason
                    logger.error(
                        "lease_loop.auth_failed worker=%s -- stopping: %s",
                        self.identity.worker_id, exc.message,
                        extra={"event": "lease_loop.auth_failed",
                               "worker_id": self.identity.worker_id,
                               "reason": exc.reason},
                    )
                    break
                logger.warning("lease_loop.lease_error reason=%s: %s", exc.reason, exc.message)
                await asyncio.sleep(self.backoff.next_delay())
                continue
            except Exception as exc:  # noqa: BLE001 -- manager unreachable / transport
                logger.warning(
                    "lease_loop.manager_unavailable error=%s -- backing off", exc,
                    extra={"event": "lease_loop.manager_unavailable",
                           "reason": REASON_MANAGER_UNAVAILABLE},
                )
                await asyncio.sleep(self.backoff.next_delay())
                continue

            self.backoff.reset()

            # PHASE 8 P8-B: the IDLE heartbeat. A worker only ever beat from inside
            # `_heartbeat_while_running`, so a worker with no work never reported at all --
            # which is precisely the state a tunnel-down alert needs to see. Rate-limited to
            # the EXISTING `heartbeat_seconds` (30s) rather than beating every poll: the
            # lease poll runs every `idle_seconds` (5s), and beating on each one would be a
            # 6x increase in manager writes for no extra signal.
            if _now() - last_beat >= self.backoff.heartbeat_seconds:
                last_beat = _now()
                await self.report_health()

            if handled == 0:
                await asyncio.sleep(self.backoff.idle_seconds)

        logger.info(
            "lease_loop.stopped worker=%s stats=%s", self.identity.worker_id, self.stats,
            extra={"event": "lease_loop.stopped", "worker_id": self.identity.worker_id},
        )
        return dict(self.stats)
