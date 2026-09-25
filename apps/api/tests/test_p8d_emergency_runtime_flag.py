"""MBS.SC PHASE 8 (P8-D) -- runtime emergency kill switch.

THE GAP THIS CLOSES
-------------------
`private_scanning_emergency_disable` is read through `get_settings()`, which is `@lru_cache`d,
so the first call freezes the value for the life of the process. Measured inside the live
scanner-manager before this landed:

    initial:                      False
    after env flip (no restart):  False
    same cached object?           True

A container's environment is immutable after start, so activating the switch required a
manager RESTART -- slow exactly when speed matters. P8-D adds a second source: a read-only
bind-mounted directory in which the operator creates or removes a sentinel file.

WHAT THESE TESTS PIN
--------------------
  * the OR truth table (env x sentinel) across all four states;
  * that the sentinel can only ever ADD restriction -- it can never re-enable scanning the
    environment disabled;
  * detection WITHOUT a restart, and removal within the TTL;
  * fail-closed behaviour on read failure, with and without a prior successful read;
  * that public scanning is unaffected in every state;
  * that both enforcement points (new leases AND in-flight work) still consult it;
  * that Phase 7 and P8-A/B/C/F are untouched.
"""
import os

import pytest

from apps.api.core import runtime_flags


class _Settings:
    """Minimal stand-in for the settings object the flag reader consults."""

    def __init__(self, disabled: bool):
        self.private_scanning_emergency_disable = disabled


@pytest.fixture(autouse=True)
def _isolated_flag_dir(tmp_path, monkeypatch):
    """Point the reader at a temp directory and drop any cached reading between tests."""
    monkeypatch.setenv("MBS_RUNTIME_FLAG_DIR", str(tmp_path))
    runtime_flags.reset_flag_cache()
    yield tmp_path
    runtime_flags.reset_flag_cache()


def _sentinel(dirpath):
    return dirpath / runtime_flags.EMERGENCY_DISABLE_SENTINEL


# --- the OR truth table -----------------------------------------------------------------

def test_env_off_and_file_absent_allows_private_scanning(_isolated_flag_dir):
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(False)) is False


def test_env_on_and_file_absent_blocks_private_scanning(_isolated_flag_dir):
    """The pre-existing environment mechanism still works, unchanged."""
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True


def test_env_off_and_file_present_blocks_private_scanning(_isolated_flag_dir):
    """THE new capability: the operator's sentinel alone disables scanning."""
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(False)) is True


def test_env_on_and_file_present_blocks_private_scanning(_isolated_flag_dir):
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True


def test_removing_the_sentinel_cannot_re_enable_what_the_env_disabled(_isolated_flag_dir):
    """THE safety invariant: a logical OR, never an override. A missing file must not be
    able to switch OFF a restriction the environment configured."""
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True
    _sentinel(_isolated_flag_dir).unlink()
    runtime_flags.reset_flag_cache()
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True


def test_the_env_half_short_circuits_without_touching_the_filesystem(monkeypatch):
    """With the env already disabled the answer cannot change, so no stat is performed."""
    calls = []
    monkeypatch.setattr(os.path, "exists", lambda p: calls.append(p) or False)
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(True)) is True
    assert calls == []


# --- no restart required, and TTL behaviour ---------------------------------------------

def test_creating_the_sentinel_is_detected_without_a_restart(_isolated_flag_dir):
    """The whole point of P8-D: the same live process observes the change."""
    s = _Settings(False)
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is False
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is True


def test_removing_the_sentinel_is_detected_within_the_ttl(_isolated_flag_dir):
    s = _Settings(False)
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is True
    _sentinel(_isolated_flag_dir).unlink()
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is False


def test_a_reading_is_cached_for_the_ttl(_isolated_flag_dir):
    """Bounded cost: the filesystem is consulted at most once per TTL, not per request."""
    s = _Settings(False)
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=3600) is False
    _sentinel(_isolated_flag_dir).touch()
    # Still inside the TTL -> the cached reading stands.
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=3600) is False
    # Expire it -> the new state is observed.
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is True


def test_the_default_ttl_is_five_seconds():
    assert runtime_flags.FLAG_TTL_SECONDS == 5.0


# --- FAIL-CLOSED on read failure --------------------------------------------------------

def test_a_read_failure_retains_the_last_known_enabled_value(_isolated_flag_dir, monkeypatch):
    """A control plane that cannot read its own kill switch must not conclude 'all clear'."""
    s = _Settings(False)
    _sentinel(_isolated_flag_dir).touch()
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is True

    def _boom(_path):
        raise OSError("filesystem unavailable")

    monkeypatch.setattr(os.path, "exists", _boom)
    # Retained, NOT reverted to False -- reverting would silently re-enable scanning.
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is True


def test_a_read_failure_retains_a_last_known_disabled_value(_isolated_flag_dir, monkeypatch):
    """Symmetry: 'retain last known' means exactly that, in both directions."""
    s = _Settings(False)
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is False

    monkeypatch.setattr(os.path, "exists", lambda p: (_ for _ in ()).throw(OSError("io")))
    assert runtime_flags.private_scanning_emergency_disabled(s, ttl=0) is False


def test_a_read_failure_with_no_previous_reading_fails_closed(monkeypatch):
    """No successful read EVER -> the safe answer is DISABLED, never False."""
    runtime_flags.reset_flag_cache()
    monkeypatch.setattr(os.path, "exists", lambda p: (_ for _ in ()).throw(OSError("io")))
    assert runtime_flags.private_scanning_emergency_disabled(_Settings(False), ttl=0) is True


def test_the_reader_never_raises_into_the_request_path(monkeypatch):
    """An exception here would take down the lease path, turning a monitoring problem into
    a scanning outage."""
    runtime_flags.reset_flag_cache()
    monkeypatch.setattr(os.path, "exists", lambda p: (_ for _ in ()).throw(RuntimeError("x")))
    runtime_flags.private_scanning_emergency_disabled(_Settings(False), ttl=0)  # must not raise


# --- both enforcement points still consult it -------------------------------------------

def test_both_manager_enforcement_points_use_the_runtime_flag():
    """New leases AND in-flight work. An emergency control that only stops NEW work is not
    an emergency control."""
    import inspect

    import apps.api.scanner_manager.app as mod

    gate = inspect.getsource(mod._authorize_scan_for_worker)   # in-flight
    lease = inspect.getsource(mod.lease_jobs)                  # new leases
    assert "private_scanning_emergency_disabled" in gate
    assert "private_scanning_emergency_disabled" in lease
    # ...and neither reads the frozen settings value directly any more.
    assert "private_scanning_emergency_disable\"" not in gate
    assert "private_scanning_emergency_disable\"" not in lease


def test_public_scanning_is_untouched_by_the_switch():
    """The check sits inside the `site_uuid is not None` branch, so a public engagement is
    never interrupted -- in ANY flag state."""
    import inspect

    import apps.api.scanner_manager.app as mod

    gate = inspect.getsource(mod._authorize_scan_for_worker)
    flag_at = gate.index("private_scanning_emergency_disabled")
    branch_at = gate.index("if site_uuid is not None")
    assert branch_at < flag_at, "the emergency check escaped the private-only branch"


def test_no_http_endpoint_can_set_the_flag():
    """The switch must stay operator/filesystem controlled -- an endpoint would give it a
    new controller, and a compromised caller a new lever."""
    import inspect

    import apps.api.scanner_manager.app as mod

    src = inspect.getsource(mod)
    assert "EMERGENCY_DISABLE_PRIVATE_SCANNING" not in src
    for verb in ("@app.post", "@app.put", "@app.patch", "@app.delete"):
        for line in src.splitlines():
            if verb in line:
                assert "emergency" not in line.lower()


def test_the_flag_module_exposes_no_setter():
    """Read-only by construction: nothing here can create or remove the sentinel."""
    import inspect

    src = inspect.getsource(runtime_flags)
    for writer in ("os.remove", "os.unlink", "open(", "touch(", "Path(", "mkdir"):
        assert writer not in src, f"runtime_flags must not write: {writer}"


# --- deployment wiring ------------------------------------------------------------------

def _compose(path):
    from pathlib import Path

    import yaml

    p = Path(__file__).resolve().parents[3] / "infra" / path
    if not p.is_file():
        pytest.skip("infra/ not bind-mounted in this environment")
    return yaml.safe_load(p.read_text(encoding="utf-8"))


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.prod.yml"])
def test_the_manager_mounts_the_runtime_directory_read_only(compose):
    svc = _compose(compose)["services"]["scanner-manager"]
    mounts = [str(v) for v in (svc.get("volumes") or [])]
    assert any(v == "./runtime:/run/mbs:ro" for v in mounts), mounts


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.prod.yml"])
def test_the_mount_is_a_directory_not_a_single_file(compose):
    """A single-file bind is inode-pinned, so an atomic `mv` replace would leave the
    container reading the OLD file forever."""
    svc = _compose(compose)["services"]["scanner-manager"]
    for v in (svc.get("volumes") or []):
        if "/run/mbs" in str(v):
            assert not str(v).split(":")[0].endswith(runtime_flags.EMERGENCY_DISABLE_SENTINEL)


def test_no_worker_can_reach_the_runtime_flag():
    """THE isolation requirement: the switch must be unreachable from the execution plane.
    No worker -- public or private -- may mount the runtime directory."""
    for compose, services in (
        ("docker-compose.yml", ["worker", "worker-default"]),
        ("docker-compose.prod.yml", ["worker", "worker-default"]),
        ("docker-compose.private-site.yml", ["worker-site-SITE_SLUG"]),
    ):
        doc = _compose(compose)
        for name in services:
            svc = (doc.get("services") or {}).get(name)
            if svc is None:
                continue
            for v in (svc.get("volumes") or []):
                assert "/run/mbs" not in str(v), f"{name} in {compose} mounts the flag dir"
                assert "runtime" not in str(v), f"{name} in {compose} mounts runtime/"


def test_the_sentinel_is_git_ignored():
    """A committed sentinel would ship a kill switch stuck ON (or mask one an operator set)."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    gi = root / ".gitignore"
    if not gi.is_file():
        pytest.skip("no .gitignore in this environment")
    text = gi.read_text(encoding="utf-8")
    assert "infra/runtime/*" in text
    assert "!infra/runtime/.gitkeep" in text


# --- REGRESSION: Phase 7 / P8-A / P8-B / P8-C / P8-F unchanged ---------------------------

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
    from datetime import datetime, timedelta, timezone

    from apps.api.scanner_manager.app import _worker_metric_lines

    now = datetime(2026, 9, 12, 0, 0, 0, tzinfo=timezone.utc)

    class _R:
        pool_id = "private-lab-a"
        site_id = "s1"
        health_state = "healthy"
        last_handshake_age_s = 40
        last_seen_at = now - timedelta(seconds=5)

    body = "\n".join(_worker_metric_lines([_R()], now=now))
    assert 'mbs_tunnel_up{pool_id="private-lab-a"} 1' in body


def test_p8f_stale_reaper_is_unchanged():
    from apps.api.modules.scanner_workers import service as ws

    assert hasattr(ws, "reap_stale_workers")
    src = __import__("inspect").getsource(ws.reap_stale_workers)
    assert "SET status = 'suspended'" in src
