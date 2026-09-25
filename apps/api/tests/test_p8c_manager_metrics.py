"""MBS.SC PHASE 8 (P8-C) -- manager-side VPN metrics export.

WHY THE METRICS ARE EXPORTED FROM THE MANAGER
---------------------------------------------
Tier 1 made every private worker EMIT tunnel health, but a private worker sits on its own
`mbs-site-<slug>` network and binds no metrics port. Scraping it directly would mean putting
Prometheus inside the execution plane -- or inside every customer's network -- which is the
boundary Phases 1/2/7 exist to enforce. So the worker REPORTS health over the existing
authenticated /v1/heartbeat, the manager persists it, and `/metrics` projects those rows.

WHAT THESE TESTS PIN
--------------------
  * the projection itself (healthy/unhealthy/never-reported/public), as a pure function;
  * LABEL DISCIPLINE -- `pool_id` only, never a tenant identifier;
  * fail-closed authentication, reusing the existing METRICS_MODE contract;
  * that a scrape failure cannot take the manager down;
  * that Phase 7 and Tier 1 behaviour are untouched.

Pure and offline: `_worker_metric_lines` needs no database and no clock of its own, so every
rule below is asserted without standing up the app.
"""
from datetime import datetime, timedelta, timezone

import pytest

from apps.api.scanner_manager.app import _escape_label, _worker_metric_lines

NOW = datetime(2026, 9, 11, 21, 0, 0, tzinfo=timezone.utc)


class _Row:
    """A stand-in for a `scanner_workers` row (the projection reads attributes only)."""

    def __init__(self, **kw):
        self.pool_id = kw.get("pool_id", "p")
        self.site_id = kw.get("site_id")
        self.workspace_id = kw.get("workspace_id")
        self.worker_id = kw.get("worker_id", "wk")
        self.health_state = kw.get("health_state", "healthy")
        self.last_handshake_age_s = kw.get("last_handshake_age_s")
        self.last_seen_at = kw.get("last_seen_at")


def _private(**kw):
    kw.setdefault("site_id", "site-uuid-1")
    kw.setdefault("workspace_id", "ws-uuid-1")
    kw.setdefault("last_seen_at", NOW - timedelta(seconds=5))
    return _Row(**kw)


def _public(**kw):
    kw.setdefault("site_id", None)
    kw.setdefault("pool_id", "public-default")
    kw.setdefault("last_seen_at", NOW - timedelta(seconds=7))
    return _Row(**kw)


def _lines(rows):
    return [ln for ln in _worker_metric_lines(rows, now=NOW) if not ln.startswith("#")]


def _value(rows, metric, pool):
    for ln in _lines(rows):
        if ln.startswith(f'{metric}{{pool_id="{pool}"}} '):
            return float(ln.rsplit(" ", 1)[1])
    return None


# --- the three metrics ------------------------------------------------------------------

def test_healthy_private_worker_reports_tunnel_up_1():
    rows = [_private(pool_id="private-lab-a", health_state="healthy")]
    assert _value(rows, "mbs_tunnel_up", "private-lab-a") == 1


def test_unhealthy_private_worker_reports_tunnel_up_0():
    rows = [_private(pool_id="private-lab-a", health_state="unhealthy")]
    assert _value(rows, "mbs_tunnel_up", "private-lab-a") == 0


def test_handshake_age_matches_the_persisted_value():
    rows = [_private(pool_id="private-lab-a", last_handshake_age_s=40)]
    assert _value(rows, "mbs_tunnel_handshake_age_seconds", "private-lab-a") == 40.0


def test_heartbeat_age_is_derived_from_last_seen_at():
    rows = [_private(pool_id="private-lab-a", last_seen_at=NOW - timedelta(seconds=42))]
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "private-lab-a") == 42.0


def test_a_future_last_seen_never_produces_a_negative_age():
    """Clock skew between the manager and the database must not emit a nonsense value."""
    rows = [_private(pool_id="p1", last_seen_at=NOW + timedelta(seconds=30))]
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "p1") == 0.0


def test_a_naive_timestamp_is_treated_as_utc_not_local():
    """MySQL hands back naive datetimes; interpreting them as local time would make the
    heartbeat age wrong by the host's UTC offset -- silently, and only in some deployments."""
    rows = [_private(pool_id="p1", last_seen_at=(NOW - timedelta(seconds=9)).replace(tzinfo=None))]
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "p1") == 9.0


# --- fail-closed projection rules -------------------------------------------------------

@pytest.mark.parametrize("state", ["unknown", "", None, "degraded", "HEALTHY-ish"])
def test_only_exactly_healthy_counts_as_up(state):
    """Anything that is not 'healthy' is 0. An unrecognised state must never read as up."""
    rows = [_private(pool_id="p1", health_state=state)]
    assert _value(rows, "mbs_tunnel_up", "p1") == 0


def test_a_worker_that_never_reported_is_emitted_as_down_not_omitted():
    """THE fail-closed rule. Omitting it would leave `mbs_tunnel_up == 0` with nothing to
    match, so a worker that never came up at all would look like a healthy fleet."""
    rows = [_private(pool_id="p-never", health_state="unknown", last_seen_at=None)]
    assert _value(rows, "mbs_tunnel_up", "p-never") == 0


def test_a_never_reported_worker_emits_no_heartbeat_age():
    rows = [_private(pool_id="p-never", last_seen_at=None)]
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "p-never") is None


def test_a_missing_handshake_age_is_absent_not_zero():
    """Rendering a missing age as 0 would read as 'handshake just happened' -- the exact
    inverse of the truth, and it would silence MbsTunnelHandshakeStale."""
    rows = [_private(pool_id="p1", last_handshake_age_s=None)]
    assert _value(rows, "mbs_tunnel_handshake_age_seconds", "p1") is None


def test_case_and_whitespace_in_health_state_are_tolerated():
    rows = [_private(pool_id="p1", health_state="  Healthy  ")]
    assert _value(rows, "mbs_tunnel_up", "p1") == 1


# --- public workers ---------------------------------------------------------------------

def test_a_public_worker_produces_no_tunnel_metric():
    """A public worker has no tunnel. Emitting up=1 for it would dilute
    `mbs_tunnel_up == 0` across pools that can never have a tunnel."""
    rows = [_public(pool_id="public-default")]
    assert _value(rows, "mbs_tunnel_up", "public-default") is None
    assert _value(rows, "mbs_tunnel_handshake_age_seconds", "public-default") is None


def test_a_public_worker_still_reports_heartbeat_age():
    """Liveness is meaningful for any worker, tunnel or not."""
    rows = [_public(pool_id="public-default")]
    assert _value(rows, "mbs_scanner_worker_heartbeat_age_seconds", "public-default") == 7.0


# --- LABEL DISCIPLINE: no tenant identifier may ever appear -----------------------------

def test_only_pool_id_is_exposed_as_a_label():
    rows = [_private(pool_id="private-lab-a", site_id="site-uuid-1",
                     workspace_id="ws-uuid-1", worker_id="worker-site-lab-a")]
    for line in _lines(rows):
        labels = line[line.index("{") + 1:line.index("}")]
        assert labels.startswith('pool_id="')
        assert labels.count("=") == 1, f"more than one label: {line}"


@pytest.mark.parametrize("secret", ["site-uuid-1", "ws-uuid-1", "worker-site-lab-a"])
def test_site_workspace_and_worker_ids_never_appear_anywhere_in_the_output(secret):
    """A metrics endpoint is the surface most likely to be forwarded to a third-party
    dashboard. Publishing site/workspace ids would leak how many private customers exist."""
    rows = [_private(pool_id="private-lab-a", site_id="site-uuid-1",
                     workspace_id="ws-uuid-1", worker_id="worker-site-lab-a")]
    body = "\n".join(_worker_metric_lines(rows, now=NOW))
    assert secret not in body


def test_a_pool_id_cannot_inject_a_second_label_or_break_the_format():
    """Operator-chosen pool ids must not be able to emit malformed exposition text."""
    rows = [_private(pool_id='evil",site_id="leak')]
    for line in _lines(rows):
        labels = line[line.index("{") + 1:line.index("}")]
        assert labels.startswith('pool_id="')
        # The injected quotes are ESCAPED, so they stay part of the pool_id VALUE and cannot
        # terminate it. Blanking each ESCAPED pair (not unescaping it) leaves only the
        # value's own delimiters -- so exactly two quotes and one `=` must remain.
        skeleton = labels.replace('\\"', "\x00")
        # Exactly TWO unescaped quotes -- the value's own delimiters. That is the property
        # that matters: the injected text cannot close pool_id and open a second label.
        # `site_id=` DOES survive as literal characters INSIDE the value, which is harmless
        # and is exactly what escaping is supposed to achieve, so `=` is not counted here.
        assert skeleton.count('"') == 2, line
        assert skeleton.index('"') == len("pool_id=")
        assert skeleton.endswith('"'), line
    assert _escape_label('a"b') == 'a\\"b'
    assert _escape_label("a\nb") == "ab"


def test_output_is_well_formed_prometheus_exposition():
    rows = [_private(pool_id="p1", last_handshake_age_s=12), _public(pool_id="pub")]
    for line in _worker_metric_lines(rows, now=NOW):
        if line.startswith("#"):
            assert line.startswith(("# HELP ", "# TYPE "))
            continue
        name, value = line.rsplit(" ", 1)
        assert name.startswith("mbs_")
        float(value)  # must parse


def test_every_declared_metric_matches_the_existing_alert_expressions():
    """The alert expressions are UNCHANGED by P8-C; these are the names they query."""
    body = "\n".join(_worker_metric_lines([_private(pool_id="p1", last_handshake_age_s=1)],
                                          now=NOW))
    for metric in ("mbs_tunnel_up", "mbs_tunnel_handshake_age_seconds",
                   "mbs_scanner_worker_heartbeat_age_seconds"):
        assert f"# TYPE {metric} gauge" in body


def test_an_empty_fleet_still_renders_valid_output():
    body = _worker_metric_lines([], now=NOW)
    assert body and all(ln.startswith("#") for ln in body)


# --- authentication + resilience (endpoint level) ---------------------------------------

def _client():
    from fastapi.testclient import TestClient

    from apps.api.scanner_manager.app import app

    return TestClient(app, raise_server_exceptions=False)


def test_unauthenticated_metrics_access_is_refused(monkeypatch):
    """Reuses the EXISTING METRICS_MODE contract -- no new credential model."""
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "token", raising=False)
    monkeypatch.setattr(s, "metrics_token", "s3cret", raising=False)
    assert _client().get("/metrics").status_code == 403


def test_a_wrong_token_is_refused(monkeypatch):
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "token", raising=False)
    monkeypatch.setattr(s, "metrics_token", "s3cret", raising=False)
    resp = _client().get("/metrics", headers={"x-metrics-token": "wrong"})
    assert resp.status_code == 403


def test_token_mode_with_no_token_configured_fails_closed(monkeypatch):
    """The documented contract: token mode + empty METRICS_TOKEN denies everyone."""
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "token", raising=False)
    monkeypatch.setattr(s, "metrics_token", "", raising=False)
    assert _client().get("/metrics", headers={"x-metrics-token": ""}).status_code == 403


def test_disabled_mode_returns_404(monkeypatch):
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "disabled", raising=False)
    assert _client().get("/metrics").status_code == 404


def test_an_unknown_mode_fails_closed(monkeypatch):
    """Anything unrecognised must require the token, never fall through to public."""
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "banana", raising=False)
    monkeypatch.setattr(s, "metrics_token", "s3cret", raising=False)
    assert _client().get("/metrics").status_code == 403


def test_a_metrics_failure_cannot_break_the_manager(monkeypatch):
    """A failed scrape is a monitoring outage; a crashed manager would be a SCANNING outage.
    The endpoint must degrade to 503 and leave the lease path untouched."""
    import apps.api.scanner_manager.app as mod
    from apps.api.core.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "metrics_mode", "public", raising=False)

    def _boom(*a, **kw):
        raise RuntimeError("database exploded")

    monkeypatch.setattr(mod, "_worker_metric_lines", _boom)
    client = _client()
    assert client.get("/metrics").status_code == 503
    # ...and the manager is still serving.
    assert client.get("/health").status_code == 200


# --- INVARIANTS: Phase 7 / Tier 1 untouched ---------------------------------------------

def test_p8c_adds_no_gate_and_no_worker_facing_behaviour():
    """The export is READ-ONLY over persisted rows: it authorizes nothing, leases nothing,
    and cannot influence whether a scan runs."""
    import inspect

    import apps.api.scanner_manager.app as mod

    src = inspect.getsource(mod._worker_metric_lines) + inspect.getsource(mod.metrics)
    # Code only -- comments legitimately DISCUSS the lease path while touching none of it.
    code = " ".join(
        ln.split("#", 1)[0] for ln in src.splitlines() if not ln.strip().startswith("#")
    )
    for forbidden in ("_claim_scan(", "assert_worker_may_take_scan", "execution_token",
                      "_finalize_status", "lease_jobs"):
        assert forbidden not in code


def test_tier1_reporting_path_is_unchanged():
    """P8-C must not have altered how the worker observes or reports health."""
    from apps.api.scanner_worker.lease_loop import LeaseLoop

    assert hasattr(LeaseLoop, "observe_tunnel_health")
    assert hasattr(LeaseLoop, "report_health")


def test_phase7_per_job_gate_is_unchanged():
    from apps.api.scanner_engine import wireguard
    from apps.api.scanner_worker.lease_loop import LeaseError, preflight_private_job

    down = wireguard.StaticTunnelProbe(wireguard.TunnelStatus(interface_up=False))
    job = {"network_zone": "private", "site_id": "s", "authorized_cidrs": ["10.90.0.0/24"]}
    with pytest.raises(LeaseError):
        preflight_private_job(job, probe=down)
    # Public scanning still unaffected.
    preflight_private_job({"network_zone": "public"}, probe=None)
