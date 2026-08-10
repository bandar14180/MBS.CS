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
        "MbsHighScanFailureRatio", "MbsExcessiveToolFailures", "MbsAiCostHigh",
        "MbsScanRecoveryActivity",
        # F4 reliability alerts
        "MbsDlqBacklog", "MbsBackupFailing", "MbsRetentionFailing",
        # DR-4 backup freshness
        "MbsBackupStale",
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
                   # DR-4 backup freshness gauge
                   "mbs_backup_age_seconds"):
        assert metric in exprs
    assert 'up{job="mbs-api"}' in exprs and 'up{job="mbs-worker"}' in exprs


def test_prod_compose_prometheus_service():
    compose = REPO_ROOT / "infra" / "docker-compose.prod.yml"
    if not compose.is_file():
        pytest.skip("infra/ not bind-mounted")
    cfg = yaml.safe_load(compose.read_text(encoding="utf-8"))
    prom = cfg["services"]["prometheus"]
    assert prom["image"].startswith("prom/prometheus:")          # pinned, not :latest
    assert prom["image"] != "prom/prometheus:latest"
    # never public -- bound to localhost only
    assert any(str(p).startswith("127.0.0.1:9090") for p in prom["ports"])
    assert "metrics_token" in prom["secrets"]                    # token via secret, not inline
    mounts = " ".join(prom["volumes"])
    assert "prometheus.yml" in mounts and "alerts.yml" in mounts


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
