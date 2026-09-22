"""AUDIT-006 (CGNAT is not public) and AUDIT-011 (a security denial must not be swallowed).

AUDIT-006 -- 100.64.0.0/10
--------------------------
net_guard classified addresses by asking Python's `ipaddress` module: is_private / is_loopback
/ is_link_local / is_multicast / is_reserved / is_unspecified. None of those is True for
RFC 6598 Shared Address Space (verified: `ipaddress.ip_address("100.64.0.1").is_private` is
False on CPython 3.12), so the guard treated 100.64/10 as ordinary public Internet and let the
scanner target it. That range carries real internal hosts -- carrier-grade NAT, container and
cloud fabrics, Tailscale's whole address space -- and Alibaba's metadata endpoint
100.100.100.200 sits inside it (it was blocked only by being listed as a metadata literal;
the /10 around it was open).

AUDIT-011 -- swallowed TargetNotAllowed
---------------------------------------
`_web.py`'s web_targets() and content_discovery_targets() wrapped the scan-time SSRF
revalidation in `except Exception: pass`. TargetNotAllowed is an Exception, so a target the
policy had just REJECTED fell through to the bare-host fallback and was returned as a normal
URL list for nuclei / katana / ffuf to attack. The denial became a silent success -- the
worst possible failure mode for a security control.

These tests pin both. The boundary cases matter as much as the blocked ones: 100.63.255.255
and 100.128.0.1 are genuinely public and must STAY scannable, or the fix has broken real scans.
"""
from __future__ import annotations

import socket

import pytest

from apps.api.scanner_engine import net_guard
from apps.api.scanner_engine.net_guard import TargetNotAllowed, is_ip_allowed
from apps.api.scanner_engine.tool_runners import _web


# --------------------------------------------------------------------------------------------
# AUDIT-006 -- CGNAT
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("addr", [
    "100.64.0.1",        # first usable address of the range
    "100.64.1.1",        # the finding's own example
    "100.127.255.254",   # last usable address of the range
    "100.64.0.0",        # network address
    "100.100.100.200",   # Alibaba cloud metadata -- inside the /10
    "100.80.12.34",      # arbitrary interior address
])
def test_cgnat_addresses_are_blocked(addr):
    """RFC 6598 shared address space is NOT the public Internet."""
    assert is_ip_allowed(addr) is False, f"{addr} (100.64.0.0/10, RFC 6598) must be blocked"


@pytest.mark.parametrize("addr", [
    "100.63.255.255",   # one below the range
    "100.128.0.1",      # one above the range
    "100.0.0.1",        # 100/8 outside the /10
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
])
def test_addresses_outside_cgnat_remain_allowed(addr):
    """The fix must block exactly 100.64.0.0/10 -- not 100/8, and not the public Internet.
    Over-blocking here would silently break legitimate customer scans."""
    assert is_ip_allowed(addr) is True, f"{addr} is public and must remain scannable"


def test_cgnat_blocked_through_ipv4_mapped_ipv6():
    """The mapped form must not smuggle a CGNAT address past the check -- _to_ip() normalizes
    it, and the range test has to run on the normalized value."""
    assert is_ip_allowed("::ffff:100.64.0.1") is False


def test_assert_ip_allowed_raises_target_not_allowed_for_cgnat():
    """The raising entry point, not just the boolean one."""
    with pytest.raises(TargetNotAllowed):
        net_guard.assert_ip_allowed("100.64.0.1")


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",   # loopback + RFC1918
    "169.254.169.254",                                       # link-local / AWS metadata
    "224.0.0.1",                                             # multicast
    "0.0.0.0",                                               # unspecified
    "240.0.0.1",                                             # reserved
    "::1", "fd00::1", "fe80::1", "ff02::1",                  # IPv6 loopback/ULA/LL/multicast
    "::ffff:10.0.0.1",                                       # IPv4-mapped private
])
def test_preexisting_ssrf_protections_are_intact(addr):
    """AUDIT-006 must not weaken anything that already worked."""
    assert is_ip_allowed(addr) is False, f"{addr} regressed -- it must stay blocked"


# --------------------------------------------------------------------------------------------
# AUDIT-011 -- TargetNotAllowed must propagate out of _web.py
# --------------------------------------------------------------------------------------------

def test_web_targets_propagates_target_not_allowed(monkeypatch):
    """THE REGRESSION LOCK. A blocked target must raise, NOT return a URL list.

    With the old `except Exception: pass`, this call returned
    ['http://blocked.example', 'https://blocked.example'] -- handing nuclei/katana a target
    the SSRF policy had already denied.
    """
    def _deny(_value):
        raise TargetNotAllowed("Address 100.64.0.1 is not permitted")

    monkeypatch.setattr(_web, "resolve_scan_host", _deny)
    with pytest.raises(TargetNotAllowed):
        _web.web_targets("blocked.example", [])


def test_content_discovery_targets_propagates_target_not_allowed(monkeypatch):
    """The second, identical swallow site -- the ffuf path."""
    def _deny(_value):
        raise TargetNotAllowed("Address 100.64.0.1 is not permitted")

    monkeypatch.setattr(_web, "resolve_scan_host", _deny)
    with pytest.raises(TargetNotAllowed):
        _web.content_discovery_targets("blocked.example", [])


@pytest.mark.parametrize("exc", [socket.gaierror("Name or service not known"), IndexError("no records")])
def test_expected_resolver_failures_are_still_handled(monkeypatch, exc):
    """Narrowing must not turn an ordinary unresolvable host into a scan-aborting error --
    that is the fail-soft behavior httpx_runner/naabu_runner also implement."""
    def _fail(_value):
        raise exc

    monkeypatch.setattr(_web, "resolve_scan_host", _fail)
    urls = _web.web_targets("nonexistent.invalid", [])
    assert urls == ["http://nonexistent.invalid", "https://nonexistent.invalid"]

    urls2 = _web.content_discovery_targets("nonexistent.invalid", [])
    assert urls2 == ["http://nonexistent.invalid", "https://nonexistent.invalid"]


def test_valid_target_still_produces_normal_targets(monkeypatch):
    """The allowed path is unchanged: validation passes, URLs are built from the ORIGINAL
    hostname (not the resolved IP), preserving Host header / SNI."""
    monkeypatch.setattr(_web, "resolve_scan_host", lambda v: "93.184.216.34")
    assert _web.web_targets("example.com", []) == ["http://example.com", "https://example.com"]
    assert _web.content_discovery_targets("example.com", []) == [
        "http://example.com", "https://example.com",
    ]


def test_web_module_has_no_blanket_exception_handler():
    """Structural guard: the bare `except Exception` that caused AUDIT-011 must not come back
    to this module. It is small and entirely on the SSRF revalidation path, so a blanket
    handler anywhere in it is a defect by construction."""
    from pathlib import Path

    src = Path(_web.__file__).read_text(encoding="utf-8")
    code = "\n".join(
        line for line in src.splitlines() if not line.strip().startswith("#")
    )
    assert "except Exception" not in code, (
        "a blanket `except Exception` in _web.py can swallow TargetNotAllowed (AUDIT-011)"
    )
    assert "except BaseException" not in code
