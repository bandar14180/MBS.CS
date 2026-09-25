"""Site-specific (split-horizon) DNS for private scanning -- MBS.SC Phase 9.

THE PROBLEM
-----------
The stack hardcodes `dns: [8.8.8.8, 1.1.1.1]` on the scanner container, and every
resolution goes through `socket.getaddrinfo`, i.e. the OS resolver. For public scanning
that is correct and stays unchanged. For a PRIVATE site it is two separate failures:

  1. DISCLOSURE. Asking Google to resolve `payroll-db.internal.acme.corp` tells a third
     party the customer's internal naming, host inventory and (by query timing) when an
     engagement runs. The query leaves the customer's tunnel entirely.
  2. WRONG ANSWER. A split-horizon name either does not resolve publicly -- so the scan
     fails confusingly -- or resolves to a DIFFERENT, attacker-influenceable public
     address. Silently scanning that address is scanning the wrong host.

So a private-site lookup must go to the site's own resolver, reached through that site's
tunnel, and must NEVER fall back to a public resolver. A failure here is a hard, explicit
failure: "the customer's resolver is unreachable" is a legitimate scan-blocking condition,
whereas a quiet fallback is a leak. Fail closed, loudly.

WHY THIS IS A SEPARATE MODULE
-----------------------------
`net_guard.resolve_hostname` keeps its exact existing OS-resolver behaviour for public
scans; this module is consulted only when a private policy names resolvers. Keeping them
apart means the public path -- the one every existing scan uses -- is untouched code.
"""
from __future__ import annotations

import logging
import socket

logger = logging.getLogger(__name__)


class SiteDNSUnavailable(socket.gaierror):
    """The site's own resolver(s) could not answer.

    Subclasses socket.gaierror deliberately: every existing caller in the scan engine
    already treats gaierror as "unresolvable, fail this target cleanly", so a resolver
    outage degrades exactly like any other resolution failure instead of crashing the
    pipeline -- while still being distinguishable when a caller wants to say WHY.
    """


class SiteDNSLeakBlocked(RuntimeError):
    """A private-site lookup was about to be answered by a public/system resolver.

    Raised rather than returning the public answer. This is the DNS-leak guard: it exists
    so the failure is visible in logs and tests, not silently papered over.
    """


# Resolver backend. Indirection exists so tests can drive split-horizon behaviour without
# a real DNS server, and so a private worker can swap in a tunnel-bound resolver. The
# default raises: no resolver configured means no private DNS, which is fail-closed.
_backend = None


def set_backend(fn) -> None:
    """Install the resolver backend: fn(hostname, resolver_ip) -> list[str] of addresses.

    Returning an empty list means NXDOMAIN/no-answer; raising OSError means the resolver
    itself was unreachable. Both are handled as failures by `resolve_via_site_dns`.
    """
    global _backend
    _backend = fn


def reset_backend() -> None:
    global _backend
    _backend = None


def get_backend():
    return _backend


def _default_backend(hostname: str, resolver: str) -> list[str]:
    """Used when no backend is installed.

    We deliberately do NOT fall back to socket.getaddrinfo here: that is precisely the
    public-resolver leak this module exists to prevent. A deployment that wants real
    split-horizon resolution installs a backend (the private worker does so at startup,
    pointing at the site's resolver through the tunnel).
    """
    raise SiteDNSUnavailable(
        f"no site-DNS backend configured; refusing to resolve private name {hostname!r} "
        f"via the public/system resolver (resolver={resolver})"
    )


def resolve_via_site_dns(
    hostname: str,
    *,
    resolvers,
    attempts: int = 3,
    retry_backoff_seconds: float = 0.2,
) -> list[str]:
    """Resolve `hostname` using ONLY the site's resolvers, in order.

    Tries each resolver; the first that answers wins. If every resolver is unreachable or
    returns no answer, raises SiteDNSUnavailable -- it never returns a public answer and
    never returns an empty list, so a caller cannot mistake "no answer" for success.
    """
    import time

    if not resolvers:
        raise SiteDNSUnavailable(
            f"private policy named no resolver for {hostname!r}; refusing public fallback"
        )
    backend = _backend or _default_backend
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        for resolver in resolvers:
            try:
                addrs = backend(hostname, resolver)
            except Exception as exc:  # resolver unreachable / backend failure
                last_error = exc
                logger.warning(
                    "site_dns.resolver_failed host=%s resolver=%s attempt=%d error=%s",
                    hostname, resolver, attempt + 1, exc,
                    extra={"event": "site_dns.resolver_failed", "resolver": resolver},
                )
                continue
            addrs = [a for a in (addrs or []) if a]
            if addrs:
                logger.info(
                    "site_dns.resolved host=%s resolver=%s count=%d",
                    hostname, resolver, len(addrs),
                    extra={"event": "site_dns.resolved", "resolver": resolver},
                )
                return addrs
            last_error = SiteDNSUnavailable(f"{resolver} returned no answer for {hostname}")
        if attempt < attempts - 1:
            time.sleep(retry_backoff_seconds * (attempt + 1))

    raise SiteDNSUnavailable(
        f"site DNS could not resolve {hostname!r} via {list(resolvers)} "
        f"({last_error}); refusing to fall back to a public resolver"
    )


# =======================================================================================
# THE PRODUCTION BACKEND (MBS.SC P7-3)
# =======================================================================================
#
# THE FINDING. Everything above was complete except that nothing in production ever called
# `set_backend()`, so `_default_backend` answered every private lookup and EVERY private
# HOSTNAME target failed closed with SiteDNSUnavailable. Private IP/CIDR targets were
# unaffected (they never resolve). The gap was the transport, not the policy.
#
# WHY THIS BACKEND HOLDS NO SITE STATE -- the load-bearing design decision.
#
# It would be natural to "install site A's resolver" before scanning site A. That would be
# WRONG here, and dangerously so: `_backend` is module-global, while scans run concurrently
# as asyncio tasks in one worker process. A global that named a site would race, and scan B
# could resolve through site A's resolver -- a cross-tenant DNS leak.
#
# It is not needed either. The resolver ADDRESS already travels with the scan: it comes
# from `ScanNetworkPolicy.dns_servers`, which `net_guard.resolve_hostname` reads from the
# task-local policy ContextVar and passes to `resolve_via_site_dns` as `resolvers`, which
# hands it to the backend per call. Site selection is therefore already per-scan and
# already concurrency-safe.
#
# So this backend is a pure, stateless TRANSPORT: "send this query to THAT resolver". It
# cannot leak between sites because it knows nothing about sites, and installing it once at
# worker startup is safe for exactly that reason.
#
# NO PUBLIC FALLBACK, STRUCTURALLY. It never consults /etc/resolv.conf, never calls
# socket.getaddrinfo, and never widens `nameservers` beyond the single resolver it was
# given. A failure raises, and `resolve_via_site_dns` turns that into SiteDNSUnavailable.

#: Per-resolver query timeout. Deliberately short: the resolver sits at the far end of the
#: site's tunnel, and a scan must not stall for minutes on a dead one. `resolve_via_site_dns`
#: already retries across resolvers and attempts, so this bounds ONE query, not the lookup.
DEFAULT_QUERY_TIMEOUT_S = 5.0


def dnspython_backend(hostname: str, resolver: str, *, timeout: float = DEFAULT_QUERY_TIMEOUT_S):
    """Query exactly ONE resolver for `hostname`'s A/AAAA records.

    Returns a list of address strings; an empty list means NXDOMAIN/no-answer, which
    `resolve_via_site_dns` treats as a failure rather than success. Raises OSError-ish
    exceptions on transport failure -- also handled as a failure there.

    `dns.resolver.Resolver(configure=False)` is the whole no-leak guarantee: `configure=True`
    (the default) would READ /etc/resolv.conf and could fall back to the namespace's own
    resolver. With configure=False the nameserver list starts EMPTY and contains only the
    resolver passed in.
    """
    import dns.resolver

    res = dns.resolver.Resolver(configure=False)
    res.nameservers = [str(resolver)]
    res.timeout = timeout
    res.lifetime = timeout
    # No search domains: a site's search list must not silently rewrite the queried name
    # into a different one. The caller asked for exactly this name.
    res.search = []

    out: list[str] = []
    seen: set[str] = set()
    last_error: Exception | None = None
    # A/AAAA only, matching what the OS-resolver path returns for the public case.
    for rdtype in ("A", "AAAA"):
        try:
            answer = res.resolve(hostname, rdtype)
        except dns.resolver.NXDOMAIN:
            # Authoritative "no such name" -- a definitive EMPTY answer, not an error. The
            # other record type may still answer, so keep going.
            continue
        except dns.resolver.NoAnswer:
            continue  # name exists, just not for this type
        except Exception as exc:  # noqa: BLE001 -- re-raised below unless the other type answered
            # Timeout / unreachable / SERVFAIL / REFUSED / malformed name. REMEMBERED, not
            # raised immediately: a resolver may legitimately serve one family and refuse
            # the other. Observed against the lab's dnsmasq, which answers A for a
            # configured name and REFUSES the AAAA -- raising here discarded a perfectly
            # good A answer and turned a working lookup into a refusal.
            #
            # Still FAIL-CLOSED: if neither type produced an address, the error is raised
            # below, so a genuinely unreachable resolver is never mistaken for NXDOMAIN.
            last_error = exc
            continue
        for rdata in answer:
            addr = str(rdata)
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
    if not out and last_error is not None:
        raise last_error
    return out


def install_default_backend(*, timeout: float = DEFAULT_QUERY_TIMEOUT_S) -> bool:
    """Install `dnspython_backend` as the process's site-DNS transport. Idempotent.

    Returns True when a backend is active afterwards, False when dnspython is unavailable
    and the fail-closed `_default_backend` therefore stays in place. It does NOT raise on a
    missing library: the correct behaviour there is to keep refusing private hostname
    lookups (exactly today's behaviour), not to prevent the worker from starting and taking
    private IP work it can still do perfectly well.

    Never overwrites a backend a caller already installed -- that is what keeps the test
    seam (and any future deployment-specific transport) authoritative over this default.
    """
    global _backend
    if _backend is not None:
        return True
    try:
        import dns.resolver  # noqa: F401
    except Exception:  # pragma: no cover - dnspython ships via email-validator
        logger.error(
            "site_dns.backend_unavailable -- dnspython is not importable; private HOSTNAME "
            "targets will continue to fail closed (private IP/CIDR targets are unaffected)",
            extra={"event": "site_dns.backend_unavailable"},
        )
        return False

    def _backend_fn(hostname: str, resolver: str):
        return dnspython_backend(hostname, resolver, timeout=timeout)

    _backend = _backend_fn
    logger.info(
        "site_dns.backend_installed timeout=%ss", timeout,
        extra={"event": "site_dns.backend_installed"},
    )
    return True
