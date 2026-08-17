"""M4.5 unit tests for scope_guard -- authorization-scope enforcement on DISCOVERED
hosts (G9). Pure; the only external dependency (DNS resolution for ip_range hostnames)
is monkeypatched. Fail-closed semantics for active probing are the core assertions."""
from dataclasses import dataclass, field

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard
from apps.api.scanner_engine.scope_guard import (
    extract_host,
    finding_in_scope,
    host_in_scope,
    partition_in_scope,
)


@dataclass
class _F:
    asset_type: str
    value: str
    metadata: dict = field(default_factory=dict)


# --- host_in_scope: domain ---

@pytest.mark.parametrize("host,expected", [
    ("example.com", True),          # apex
    ("www.example.com", True),      # subdomain
    ("a.b.example.com", True),      # nested subdomain
    ("Example.COM", True),          # case-insensitive
    ("example.com.", True),         # trailing dot normalized
    ("notexample.com", False),      # suffix-but-not-subdomain
    ("example.com.evil.com", False),# scope not a prefix of another domain
    ("evilexample.com", False),
    ("", False),                    # fail closed: empty
    (None, False),                  # fail closed: none
])
def test_host_in_scope_domain(host, expected):
    assert host_in_scope("domain", "example.com", host) is expected


def test_host_in_scope_domain_target_with_scheme_port():
    # Target value normalized (scheme/port stripped) before matching.
    assert host_in_scope("domain", "https://example.com:443", "api.example.com") is True


# --- host_in_scope: ip_range ---

def test_host_in_scope_ip_bare_and_cidr():
    assert host_in_scope("ip_range", "203.0.113.20", "203.0.113.20") is True   # /32 match
    assert host_in_scope("ip_range", "203.0.113.20", "203.0.113.21") is False  # different host
    assert host_in_scope("ip_range", "10.0.0.0/24", "10.0.0.7") is True        # within CIDR
    assert host_in_scope("ip_range", "10.0.0.0/24", "10.0.1.7") is False       # outside CIDR


def test_host_in_scope_ip_hostname_resolution(monkeypatch):
    # A hostname is in scope only if EVERY resolved address is within the range.
    monkeypatch.setattr(net_guard, "resolve_hostname", lambda h: ["10.0.0.5"])
    assert host_in_scope("ip_range", "10.0.0.0/24", "in.example.com") is True
    monkeypatch.setattr(net_guard, "resolve_hostname", lambda h: ["10.0.0.5", "8.8.8.8"])
    assert host_in_scope("ip_range", "10.0.0.0/24", "mixed.example.com") is False  # one outside
    def _boom(h):
        raise OSError("unresolvable")
    monkeypatch.setattr(net_guard, "resolve_hostname", _boom)
    assert host_in_scope("ip_range", "10.0.0.0/24", "dead.example.com") is False   # fail closed


def test_unknown_target_type_is_out_of_scope():
    assert host_in_scope("repo", "example.com", "example.com") is False


# --- M4.6.4 / F1: explicit exclude deny-list (narrowing-only) ---

def test_exclude_removes_in_domain_host_but_not_apex_or_others(monkeypatch):
    monkeypatch.setattr(get_settings(), "scan_derived_scope_excludes", ["cdn.example.com"])
    assert host_in_scope("domain", "example.com", "cdn.example.com") is False         # exact match excluded
    assert host_in_scope("domain", "example.com", "assets.cdn.example.com") is False  # parent-suffix excluded
    assert host_in_scope("domain", "example.com", "api.example.com") is True          # unrelated in-scope host kept
    assert host_in_scope("domain", "example.com", "example.com") is True              # apex NOT excluded


def test_exclude_applies_to_ip_range(monkeypatch):
    monkeypatch.setattr(get_settings(), "scan_derived_scope_excludes", ["10.0.0.5"])
    assert host_in_scope("ip_range", "10.0.0.0/24", "10.0.0.5") is False   # excluded
    assert host_in_scope("ip_range", "10.0.0.0/24", "10.0.0.6") is True    # not excluded


def test_exclude_is_narrowing_only_cannot_authorize(monkeypatch):
    # An exclude entry can never bring an out-of-scope host INTO scope.
    monkeypatch.setattr(get_settings(), "scan_derived_scope_excludes", ["evil.com"])
    assert host_in_scope("domain", "example.com", "evil.com") is False     # still out (name check)


def test_exclude_empty_default_preserves_name_based_scope(monkeypatch):
    monkeypatch.setattr(get_settings(), "scan_derived_scope_excludes", [])
    assert host_in_scope("domain", "example.com", "api.example.com") is True   # unchanged default


# --- extract_host across asset types ---

def test_extract_host_prefers_metadata_then_value():
    assert extract_host(_F("http_service", "http://10.0.0.1:3000", {"host": "10.0.0.1"})) == "10.0.0.1"
    assert extract_host(_F("service", "10.0.0.1:22", {"ip": "10.0.0.1"})) == "10.0.0.1"
    assert extract_host(_F("subdomain", "api.example.com")) == "api.example.com"
    assert extract_host(_F("url", "https://x.example.com/a?b=1")) == "x.example.com"


def test_extract_host_indeterminable_is_none():
    assert extract_host(_F("weird", "")) is None
    assert extract_host(_F("weird", None)) is None


# --- finding_in_scope + partition (fail closed) ---

def test_finding_without_host_is_out_of_scope():
    # Fail closed: a finding whose host cannot be determined is NOT probeable.
    assert finding_in_scope("domain", "example.com", _F("weird", "")) is False


def test_partition_separates_in_and_out_of_scope():
    findings = [
        _F("subdomain", "api.example.com"),          # in
        _F("subdomain", "evil.attacker.com"),        # out (unrelated domain)
        _F("http_service", "http://example.com"),    # in (apex)
        _F("weird", ""),                              # out (no host -> fail closed)
    ]
    in_scope, out = partition_in_scope("domain", "example.com", findings)
    assert [f.value for f in in_scope] == ["api.example.com", "http://example.com"]
    assert [f.value for f in out] == ["evil.attacker.com", ""]


def test_partition_ip_range():
    findings = [
        _F("service", "10.0.0.5:80", {"ip": "10.0.0.5"}),   # in CIDR
        _F("port", "10.0.9.9:443", {"ip": "10.0.9.9"}),     # outside CIDR
    ]
    in_scope, out = partition_in_scope("ip_range", "10.0.0.0/24", findings)
    assert [f.value for f in in_scope] == ["10.0.0.5:80"]
    assert [f.value for f in out] == ["10.0.9.9:443"]
