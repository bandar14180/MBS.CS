"""Per-scan network authorization policy (MBS.SC Phase 2).

WHY THIS EXISTS
---------------
`net_guard` answers "is this address safe to talk to at all?" purely from GLOBAL
settings -- `scan_allow_private_targets` + `scan_allowed_cidrs`. That is a sound SSRF
answer and it is preserved verbatim; it is NOT a sound multi-tenant AUTHORIZATION answer.

The defect it leaves behind: those two settings are process-wide. Turning the flag on for
ONE on-prem customer turned it on for EVERY tenant in the deployment, and every CIDR in
the list became scannable by every workspace. The address check could not even express
"tenant A may reach 10.1.0.0/16, tenant B may not" -- `is_ip_allowed(ip)` takes no
workspace, no scan, no site. Authorization was a global boolean.

This module supplies the missing dimension: an IMMUTABLE, per-scan policy derived from
PERSISTED authorization (workspace -> private site -> authorized CIDRs), which narrows --
and can never widen -- what net_guard already permits.

THE TWO-KEY RULE
----------------
A private destination is permitted only when BOTH agree:

  1. the GLOBAL settings still allow it   (the outer safety boundary, unchanged)
  2. THIS scan's policy allows it         (tenant-specific authorization, new)

Neither can grant on its own. Global config is a ceiling, never a grant -- so
`scan_allow_private_targets=true` no longer authorizes anybody; it only stops forbidding.
That is the precise inversion the remediation requires.

FAIL-CLOSED BY CONSTRUCTION
---------------------------
When no policy is bound, `current()` returns None and net_guard falls back to
PUBLIC-ONLY. An unbound context is the most restrictive state, not the most permissive
one, so a code path that forgets to bind a policy loses private access rather than
silently gaining it. There is no "allow everything" policy value and no way to spell one:
`PUBLIC_ONLY` is the only policy constructible without authorized CIDRs.
"""
from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import uuid
from dataclasses import dataclass, field
from typing import Iterator


class PolicyViolation(ValueError):
    """A destination was refused by the per-scan policy (as opposed to by the
    address-safety SSRF rules, which raise net_guard.TargetNotAllowed)."""


def _parse_cidrs(values) -> tuple[ipaddress._BaseNetwork, ...]:
    """Parse and DEDUPLICATE CIDRs, skipping malformed entries.

    A malformed entry is dropped rather than widened to something permissive -- dropping
    it can only ever REMOVE authorization, which is the safe direction to fail."""
    nets: list[ipaddress._BaseNetwork] = []
    seen: set[str] = set()
    for raw in values or ():
        entry = str(raw).strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(net)
    return tuple(nets)


@dataclass(frozen=True)
class ScanNetworkPolicy:
    """The effective network authorization for ONE scan execution.

    Frozen: once the orchestrator derives it from persisted authorization, nothing
    downstream -- no tool runner, no AI planner, no redirect handler -- can widen it.
    A tool runner that wanted more access would have to construct a new policy, which
    only the authorization path does.
    """

    workspace_id: uuid.UUID | None = None
    scan_id: uuid.UUID | None = None
    # public | private. A `public` policy authorizes NO private CIDR at all, whatever
    # the global settings say.
    network_zone: str = "public"
    site_id: uuid.UUID | None = None
    worker_id: str | None = None
    pool_id: str | None = None
    # The ONLY private ranges this scan may reach. Empty on a public scan.
    authorized_cidrs: tuple = field(default_factory=tuple)
    # Site-specific resolvers (Phase 9). Empty -> public resolvers.
    dns_servers: tuple = field(default_factory=tuple)

    @property
    def is_private(self) -> bool:
        return self.network_zone == "private"

    def allows_private_ip(self, ip) -> bool:
        """Whether THIS scan is authorized for a non-public address.

        A public-zone scan always returns False, so the global on-prem allowlist can
        never leak into an ordinary public engagement.
        """
        if not self.is_private:
            return False
        return any(ip.version == net.version and ip in net for net in self.authorized_cidrs)

    def describe(self) -> str:
        """Operator-facing summary for logs/errors. Contains no secrets."""
        if not self.is_private:
            return "public-only policy (no private CIDR authorized)"
        cidrs = ", ".join(str(n) for n in self.authorized_cidrs) or "(none)"
        return f"private policy site={self.site_id} authorized_cidrs=[{cidrs}]"


# The fail-closed default: authorizes nothing beyond public addresses.
PUBLIC_ONLY = ScanNetworkPolicy()

_current: contextvars.ContextVar = contextvars.ContextVar(
    "mbs_scan_network_policy", default=None
)


def current():
    """The policy bound to this execution context, or None if unbound.

    None is meaningful and SAFE: net_guard treats it as public-only. Callers must not
    substitute a permissive default for it."""
    return _current.get()


def current_or_public() -> ScanNetworkPolicy:
    return _current.get() or PUBLIC_ONLY


def set_policy(policy):
    return _current.set(policy)


def reset_policy(token) -> None:
    _current.reset(token)


@contextlib.contextmanager
def bind(policy) -> Iterator:
    """Bind `policy` for the duration of the block, restoring the previous one after.

    A ContextVar is used (rather than threading the policy through every tool-runner
    signature) because the scanner pipeline is deep and asynchronous: orchestrator ->
    runner -> _web/_net helper -> net_guard. Each `asyncio` task and each thread gets
    its own copy of the context, so two scans running concurrently in the same worker
    process CANNOT observe each other's policy -- which is what makes the "concurrent
    tenant scans stay isolated" requirement hold. Every public net_guard entry point
    also accepts an explicit `policy=` argument for callers that prefer to be explicit
    (and for tests that assert one specific policy).
    """
    token = _current.set(policy)
    try:
        yield policy
    finally:
        _current.reset(token)


def build_public_policy(*, workspace_id=None, scan_id=None) -> ScanNetworkPolicy:
    return ScanNetworkPolicy(workspace_id=workspace_id, scan_id=scan_id, network_zone="public")


def build_private_policy(
    *,
    workspace_id,
    scan_id,
    site_id,
    authorized_cidrs,
    dns_servers=(),
    worker_id=None,
    pool_id=None,
) -> ScanNetworkPolicy:
    """Construct a private policy from ALREADY-AUTHORIZED persisted values.

    This function does not itself decide authorization -- callers must have loaded the
    site and confirmed it belongs to `workspace_id` and is active (see
    modules/private_sites/service.py::build_scan_network_policy, which is the only
    intended caller). Passing no CIDRs yields a policy that authorizes nothing, which
    is the correct fail-closed outcome for a misconfigured site.
    """
    return ScanNetworkPolicy(
        workspace_id=workspace_id,
        scan_id=scan_id,
        network_zone="private",
        site_id=site_id,
        authorized_cidrs=_parse_cidrs(authorized_cidrs),
        dns_servers=tuple(str(d).strip() for d in (dns_servers or ()) if str(d).strip()),
        worker_id=worker_id,
        pool_id=pool_id,
    )
