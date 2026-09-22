"""Phase 4.2 -- verification for the Prometheus monitoring config (scrape jobs, alert rules,
prod compose service). Repo-root infra/ isn't bind-mounted in the dev container, so these
skip there and assert fully on a complete checkout (CI/host).
"""
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
PROM_DIR = REPO_ROOT / "infra" / "prometheus"


def _load(rel: Path) -> dict:
    if not rel.is_file():
        pytest.skip(f"{rel} not present in this environment (infra/ not bind-mounted)")
    return yaml.safe_load(rel.read_text(encoding="utf-8"))


def test_prometheus_scrape_config():
    cfg = _load(PROM_DIR / "prometheus.yml")
    jobs = {s["job_name"]: s for s in cfg["scrape_configs"]}
    assert "mbs-api" in jobs and "mbs-worker" in jobs
    assert jobs["mbs-api"]["static_configs"][0]["targets"] == ["api:8000"]
    # F1 topology split: both worker processes are scraped (scans on `worker`, control-plane
    # incl. reaper/relay/schedule/retention on `worker-default`).
    assert jobs["mbs-worker"]["static_configs"][0]["targets"] == ["worker:9100", "worker-default:9100"]
    # alert rules are wired in
    assert any("alerts.yml" in r for r in cfg["rule_files"])


def test_prometheus_config_holds_no_inline_secret():
    raw = (PROM_DIR / "prometheus.yml")
    if not raw.is_file():
        pytest.skip("infra/ not bind-mounted")
    text = raw.read_text(encoding="utf-8")
    # the API token must come from a mounted secret file, never a literal in the config
    assert "/run/secrets/metrics_token" in text
    cfg = yaml.safe_load(text)
    hh = cfg["scrape_configs"][0]["http_headers"]["X-Metrics-Token"]
    assert hh.get("files") and not hh.get("values")   # file-based, no inline value


def test_alert_rules_present_and_well_formed():
    cfg = _load(PROM_DIR / "alerts.yml")
    names, severities = set(), set()
    for group in cfg["groups"]:
        for rule in group["rules"]:
            assert rule.get("expr") and rule.get("labels", {}).get("severity")
            names.add(rule["alert"])
            severities.add(rule["labels"]["severity"])
    for expected in (
        "MbsApiDown", "MbsWorkerDown", "MbsApiHighServerErrorRate",
        # A: dependency health
        "MbsDependencyDown",
        "MbsHighScanFailureRatio", "MbsExcessiveToolFailures", "MbsAiCostHigh",
        "MbsScanRecoveryActivity",
        # F4 reliability alerts
        "MbsDlqBacklog", "MbsBackupFailing", "MbsRetentionFailing",
        # scan-queue backlog
        "MbsScanQueueBacklog",
        # DR-4 backup freshness
        "MbsBackupStale",
        # P1.1 beat liveness
        "MbsBeatStalled",
        # E5 email alert delivery
        "MbsEmailDeliveryFailing",
        # AI-2.2A budget enforcement
        "MbsAiBudgetBlocking",
        # AI-2.5 observability SLOs
        "MbsAiLatencySlo", "MbsAiErrorRateHigh", "MbsAiFailoverActive",
    ):
        assert expected in names, f"missing alert {expected}"
    assert {"critical", "warning"} <= severities


def test_alert_expressions_reference_existing_metrics():
    cfg = _load(PROM_DIR / "alerts.yml")
    exprs = " ".join(r["expr"] for g in cfg["groups"] for r in g["rules"])
    # every metric referenced is one we actually export (core/observability.py) or `up`
    for metric in ("mbs_http_requests_total", "mbs_scan_failed_total", "mbs_scan_success_total",
                   "mbs_tool_failure_total", "mbs_ai_cost_usd_total",
                   "mbs_scan_reaped_total", "mbs_scan_relayed_total",
                   # F4 reliability metrics (exposed by the API ReliabilityCollector)
                   "mbs_dlq_depth", "mbs_backup_failures_total", "mbs_retention_failures_total",
                   # scan-queue backlog gauge
                   "mbs_queue_depth",
                   # DR-4 backup freshness gauge
                   "mbs_backup_age_seconds",
                   # P1.1 beat-liveness gauge
                   "mbs_beat_age_seconds",
                   # A dependency-health gauge
                   "mbs_dependency_up",
                   # E5 email delivery
                   "mbs_email_failed_total",
                   # AI-2.2A budget enforcement
                   "mbs_ai_budget_blocked_total",
                   # AI-2.5 observability SLOs
                   "mbs_ai_latency_seconds", "mbs_ai_errors_total", "mbs_ai_failover_total",
                   # Phase 8 hardening: lease-eligible worker capacity (scanner-manager
                   # /metrics). Status-derived, so it stays meaningful when a suspended
                   # fleet stops heartbeating and the liveness metrics go quiet.
                   "mbs_scanner_workers_lease_eligible", "mbs_scanner_workers_registered"):
        assert metric in exprs
    assert 'up{job="mbs-api"}' in exprs and 'up{job="mbs-worker"}' in exprs


def test_prod_compose_prometheus_service():
    compose = REPO_ROOT / "infra" / "docker-compose.prod.yml"
    if not compose.is_file():
        pytest.skip("infra/ not bind-mounted")
    cfg = yaml.safe_load(compose.read_text(encoding="utf-8"))
    prom = cfg["services"]["prometheus"]
    # AUDIT-005 strengthened this: the image must be pinned by IMMUTABLE DIGEST, not merely
    # by a non-latest tag. A tag can be repointed by the publisher at any time, so
    # `prom/prometheus:v2.54.1` was still a moving reference. Was:
    #   assert prom["image"].startswith("prom/prometheus:")   # pinned, not :latest
    assert prom["image"].startswith("prom/prometheus@sha256:"), (
        f"prometheus image must be digest-pinned, got {prom['image']!r}"
    )
    assert ":latest" not in prom["image"]
    # never public -- bound to localhost only
    assert any(str(p).startswith("127.0.0.1:9090") for p in prom["ports"])
    assert "metrics_token" in prom["secrets"]                    # token via secret, not inline
    mounts = " ".join(prom["volumes"])
    assert "prometheus.yml" in mounts and "alerts.yml" in mounts


def test_prometheus_wires_alertmanager():
    """R4: Prometheus routes fired alerts to the Alertmanager service."""
    cfg = _load(PROM_DIR / "prometheus.yml")
    ams = cfg.get("alerting", {}).get("alertmanagers", [])
    targets = [t for am in ams for sc in am.get("static_configs", []) for t in sc.get("targets", [])]
    assert "alertmanager:9093" in targets, "Prometheus must point at the alertmanager service"


def test_alertmanager_config_email_via_secret():
    """R4: Alertmanager emails alerts using the SHARED smtp_password secret (never an inline
    password), routed to an email receiver that has a recipient."""
    am_p = REPO_ROOT / "infra" / "alertmanager" / "alertmanager.yml"
    if not am_p.is_file():
        pytest.skip("infra/ not present in this environment")
    am = yaml.safe_load(am_p.read_text(encoding="utf-8"))
    g = am["global"]
    assert g.get("smtp_auth_password_file") == "/run/secrets/smtp_password"   # secret via file
    assert "smtp_auth_password" not in g                                       # never inline
    assert g.get("smtp_smarthost") and g.get("smtp_from")
    assert am["route"]["receiver"] == "email"
    receivers = {r["name"]: r for r in am["receivers"]}
    assert "email" in receivers
    ec = receivers["email"].get("email_configs")
    assert ec and ec[0].get("to"), "email receiver must have a recipient"


def test_prod_compose_alertmanager_service():
    """R4: Alertmanager runs in the prod overlay -- pinned image, localhost-only, mounts its config,
    uses the smtp_password secret; the secret + durable data volume are declared, and Prometheus
    depends on it."""
    compose = REPO_ROOT / "infra" / "docker-compose.prod.yml"
    if not compose.is_file():
        pytest.skip("infra/ not present in this environment")
    cfg = yaml.safe_load(compose.read_text(encoding="utf-8"))
    am = cfg["services"]["alertmanager"]
    # AUDIT-005: immutable digest, not just a non-latest tag (see the prometheus test above).
    assert am["image"].startswith("prom/alertmanager@sha256:"), (
        f"alertmanager image must be digest-pinned, got {am['image']!r}"
    )
    assert ":latest" not in am["image"]
    assert any(str(p).startswith("127.0.0.1:9093") for p in am["ports"])   # never public
    assert "smtp_password" in am["secrets"]
    assert any("alertmanager.yml" in str(v) for v in am["volumes"])
    assert "smtp_password" in cfg["secrets"]                               # secret declared
    assert "alertmanager_data" in cfg.get("volumes", {})                  # durable state volume
    assert "alertmanager" in cfg["services"]["prometheus"]["depends_on"]


def test_dr1_backup_durability_and_prod_enablement():
    """DR-1: backups persist across container recreation (named volume) and are enabled +
    encrypted in the production overlay."""
    base_p = REPO_ROOT / "infra" / "docker-compose.yml"
    prod_p = REPO_ROOT / "infra" / "docker-compose.prod.yml"
    if not base_p.is_file() or not prod_p.is_file():
        pytest.skip("infra/ not bind-mounted")

    base = yaml.safe_load(base_p.read_text(encoding="utf-8"))
    wd = base["services"]["worker-default"]
    assert any("backup_data:/srv/backups" in str(v) for v in wd.get("volumes", [])), \
        "worker-default must mount the durable backup_data volume"
    assert "backup_data" in base.get("volumes", {}), "backup_data named volume must be declared"

    prod = yaml.safe_load(prod_p.read_text(encoding="utf-8"))
    wdp = prod["services"]["worker-default"]
    assert wdp["environment"]["BACKUP_ENABLED"] == "true"
    assert wdp["environment"]["BACKUP_ENCRYPTION_ENABLED"] == "true"
    assert "backup_encryption_key" in wdp["secrets"]           # DR-2 key via Docker Secret
    assert "backup_encryption_key" in prod["secrets"]          # secret declared
    # beat must also see the flag so it registers the scheduled-backup tick
    assert prod["services"]["beat"]["environment"]["BACKUP_ENABLED"] == "true"


def test_r1a_redis_durability_aof_and_volume():
    """R1a: Redis persists across container recreation -- AOF enabled + /data on a named volume,
    so the broker/DLQ + rate-limit/AI-budget/MFA-lockout counters + reliability freshness
    timestamps survive a restart (previously default RDB wrote to an unmounted /data and was lost).
    Asserted on the base compose; the prod overlay inherits it (no separate redis block)."""
    base_p = REPO_ROOT / "infra" / "docker-compose.yml"
    if not base_p.is_file():
        pytest.skip("infra/ not bind-mounted")
    base = yaml.safe_load(base_p.read_text(encoding="utf-8"))
    redis = base["services"]["redis"]
    raw_cmd = redis.get("command", "")
    cmd = " ".join(raw_cmd) if isinstance(raw_cmd, list) else str(raw_cmd)
    assert "--appendonly yes" in cmd, "Redis must enable AOF persistence"
    assert any("redis_data:/data" in str(v) for v in redis.get("volumes", [])), \
        "Redis must persist /data on the durable redis_data volume"
    assert "redis_data" in base.get("volumes", {}), "redis_data named volume must be declared"
    # durability must not be undermined by an eviction policy that could drop broker/DLQ keys
    assert "maxmemory-policy" not in cmd or "noeviction" in cmd
    # existing operational guarantees are preserved (not weakened by this change)
    assert redis.get("restart") == "unless-stopped"
    assert redis.get("healthcheck", {}).get("test")


def _svc_env(service: dict) -> dict:
    env = service.get("environment", {})
    if isinstance(env, list):   # normalize the "KEY=VALUE" list form to a mapping
        return dict(e.split("=", 1) for e in env if "=" in e)
    return env or {}


def test_worker_prefork_multiproc_config():
    """W1: worker + worker-default aggregate prefork-child metrics -- each sets
    PROMETHEUS_MULTIPROC_DIR and mounts a tmpfs at that SAME path (they must ship together, else the
    worker crashes creating metric files in a missing dir). The API must NOT set it -- multiprocess
    mode is incompatible with its custom collectors (ReliabilityCollector/DependencyHealthCollector)."""
    base_p = REPO_ROOT / "infra" / "docker-compose.yml"
    if not base_p.is_file():
        pytest.skip("infra/ not present in this environment")
    services = yaml.safe_load(base_p.read_text(encoding="utf-8"))["services"]
    for svc in ("worker", "worker-default"):
        mp = _svc_env(services[svc]).get("PROMETHEUS_MULTIPROC_DIR")
        assert mp, f"{svc} must set PROMETHEUS_MULTIPROC_DIR"
        tmpfs_targets = [
            v.get("target") for v in services[svc].get("volumes", [])
            if isinstance(v, dict) and v.get("type") == "tmpfs"
        ]
        assert mp in tmpfs_targets, f"{svc} must mount a tmpfs at {mp} (crash-safe + empty per run)"
    # the API is multi-process (uvicorn --workers) but uses custom collectors -> multiprocess OFF
    assert "PROMETHEUS_MULTIPROC_DIR" not in _svc_env(services["api"])


def test_retention_p1_stage1_enabled_dry_run():
    """P1 Stage 1: retention is SCHEDULED in production but PLAN-ONLY -- enabled on both
    worker-default (executes) and beat (schedules), and dry-run stays true so nothing is deleted
    until an operator explicitly flips it (see docs/runbooks/retention.md)."""
    prod_p = REPO_ROOT / "infra" / "docker-compose.prod.yml"
    if not prod_p.is_file():
        pytest.skip("infra/ not bind-mounted")
    prod = yaml.safe_load(prod_p.read_text(encoding="utf-8"))
    for svc in ("worker-default", "beat"):
        env = prod["services"][svc]["environment"]
        assert env["RETENTION_ENABLED"] == "true", f"{svc} must schedule retention"
        # Stage 1 safety: live deletion must NOT be enabled yet.
        assert env["RETENTION_DRY_RUN"] == "true", f"{svc} must stay plan-only (dry-run)"
