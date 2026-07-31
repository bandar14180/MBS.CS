"""SSRF / internal-target protection tests (P0). Pure -- DNS is monkeypatched."""
import socket

import pytest

from apps.api.core.config import get_settings
from apps.api.scanner_engine import net_guard
from apps.api.scanner_engine.net_guard import (
    TargetNotAllowed,
    is_ip_allowed,
    resolve_and_validate,
    validate_target_value,
)


@pytest.fixture(autouse=True)
def _default_policy(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", False)
    monkeypatch.setattr(s, "scan_allowed_cidrs", [])
    yield


def _fake_dns(mapping):
    def _f(host, *a, **k):
        if host not in mapping:
            raise socket.gaierror(f"cannot resolve {host}")
        return [(socket.AF_INET, 0, 0, "", (ip, 0)) for ip in mapping[host]]
    return _f


# --- forbidden vs public single IPs ---

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "::1",                     # loopback
    "10.0.0.1", "192.168.1.1", "172.16.5.5",  # RFC1918
    "169.254.1.1", "fe80::1",              # link-local
    "fc00::1", "fd00::1",                  # IPv6 ULA (private)
    "169.254.169.254", "fd00:ec2::254",   # cloud metadata
    "0.0.0.0", "::",                        # unspecified
    "224.0.0.1", "ff02::1",               # multicast
    "::ffff:10.0.0.1", "::ffff:127.0.0.1",  # IPv4-mapped IPv6 must not smuggle private
])
def test_forbidden_ips_blocked(ip):
    assert is_ip_allowed(ip) is False


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert is_ip_allowed(ip) is True


def test_malformed_addresses_blocked():
    assert is_ip_allowed("not-an-ip") is False
    assert is_ip_allowed("") is False
    assert is_ip_allowed("999.999.999.999") is False


# --- explicit on-prem allowlist ---

def test_private_allowlisted_range(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["10.20.0.0/16"])
    assert is_ip_allowed("10.20.5.5") is True
    assert is_ip_allowed("10.99.0.1") is False    # outside the allowlist
    assert is_ip_allowed("192.168.1.1") is False  # different private range


def test_metadata_blocked_even_with_broad_allowlist(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["169.254.0.0/16"])  # broad range
    assert is_ip_allowed("169.254.169.254") is False  # needs an explicit host entry


def test_metadata_allowed_only_with_explicit_host(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scan_allow_private_targets", True)
    monkeypatch.setattr(s, "scan_allowed_cidrs", ["169.254.169.254/32"])
    assert is_ip_allowed("169.254.169.254") is True


def test_allowlist_ignored_when_flag_off(monkeypatch):
    monkeypatch.setattr(get_settings(), "scan_allowed_cidrs", ["10.0.0.0/8"])
    # scan_allow_private_targets stays False -> allowlist has no effect
    assert is_ip_allowed("10.0.0.5") is False


# --- hostname resolution + DNS rebinding ---

def test_hostname_resolving_private_blocked(monkeypatch):
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_dns({"evil.test": ["10.0.0.5"]}))
    with pytest.raises(TargetNotAllowed):
        resolve_and_validate("evil.test")


def test_hostname_resolving_public_ok(monkeypatch):
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_dns({"ok.test": ["93.184.216.34"]}))
    assert resolve_and_validate("ok.test") == "93.184.216.34"


def test_rebinding_mixed_public_private_blocked(monkeypatch):
    # public + private in the same answer -> rejected (rebinding defense).
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_dns({"m.test": ["93.184.216.34", "10.0.0.1"]}))
    with pytest.raises(TargetNotAllowed):
        resolve_and_validate("m.test")


def test_cidr_passthrough_unchanged():
    # public CIDR validates and is returned unchanged (nmap scans the whole range).
    assert resolve_and_validate("93.184.216.0/24") == "93.184.216.0/24"


def test_private_cidr_rejected_at_resolution():
    with pytest.raises(TargetNotAllowed):
        resolve_and_validate("10.0.0.0/24")


# --- creation-time validation ---

def test_creation_blocks_localhost():
    with pytest.raises(TargetNotAllowed):
        validate_target_value("domain", "localhost")


def test_creation_blocks_private_ip_range():
    with pytest.raises(TargetNotAllowed):
        validate_target_value("ip_range", "10.0.0.0/24")


def test_creation_allows_public_ip_range():
    validate_target_value("ip_range", "93.184.216.0/24")  # no raise


def test_creation_strips_scheme_port_path():
    with pytest.raises(TargetNotAllowed):
        validate_target_value("domain", "https://127.0.0.1:8443/admin")


def test_creation_unresolvable_hostname_allowed(monkeypatch):
    monkeypatch.setattr(net_guard.socket, "getaddrinfo", _fake_dns({}))
    validate_target_value("domain", "future.example.com")  # allowed; runtime enforces


def test_creation_skips_non_network_types():
    # repo/api/cloud_account aren't network-scannable -> not IP-checked here.
    validate_target_value("repo", "10.0.0.1")  # no raise
