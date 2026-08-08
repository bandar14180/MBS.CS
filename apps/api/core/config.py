import os
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Secrets that may be delivered via a `<NAME>_FILE` env var pointing at a file
# (Docker Secrets mount secrets at /run/secrets/*, Vault Agent can template to a
# file). Resolving these into the plain env var before Settings() is constructed
# keeps the rest of the app oblivious to *how* the secret arrived -- the
# Vault-ready seam without taking a Vault dependency now.
_FILE_BACKED_SECRETS = (
    "JWT_SECRET_KEY",
    "DATABASE_URL",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "METRICS_TOKEN",
)

# Placeholder / insecure defaults that must never survive into production.
_INSECURE_JWT_SECRETS = {"", "change-me-in-.env", "change-me-generate-a-real-secret"}


def _resolve_file_secrets() -> None:
    """For each `<NAME>_FILE` env var, read the file and populate `<NAME>` (unless
    already set explicitly). Safe to call repeatedly; never raises on a missing
    file (a bad path simply leaves the base var unset, caught by validation)."""
    for name in _FILE_BACKED_SECRETS:
        file_var = f"{name}_FILE"
        path = os.environ.get(file_var)
        if path and not os.environ.get(name):
            try:
                with open(path, encoding="utf-8") as fh:
                    os.environ[name] = fh.read().strip()
            except OSError:
                # Leave unset; validate_production() / lazy checks surface it.
                continue


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "MBS.SC API"
    api_v1_prefix: str = "/api/v1"
    environment: str = "development"

    database_url: str = "postgresql+asyncpg://mbs:mbs@postgres:5432/mbs"
    redis_url: str = "redis://redis:6379/0"

    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket_evidence: str = "mbs-evidence"
    s3_bucket_reports: str = "mbs-reports"
    # Object-storage backend behind the StorageProvider interface. "s3" covers
    # MinIO + AWS S3 (default); azure_blob / gcs are future implementations.
    storage_provider: str = "s3"

    jwt_secret_key: str = "change-me-in-.env"
    jwt_access_token_ttl_minutes: int = 15
    jwt_refresh_token_ttl_days: int = 7

    # --- AI Agent Service ---------------------------------------------------
    # Which provider the AI layer uses. Business logic never reads this -- only
    # the provider factory (apps/api/ai_agent/providers/factory.py) does. All
    # providers conform to the SupportsComplete protocol, so switching is a
    # config change, not a code change.
    ai_provider: str = "openrouter"  # openrouter | anthropic

    # OpenRouter (primary). OpenAI-compatible; a single integration can proxy
    # Claude/GPT/Gemini/open models -- pick the model with OPENROUTER_MODEL.
    openrouter_api_key: str = ""
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    # OpenRouter model slug. Overridable per environment; must match a slug from
    # https://openrouter.ai/models (e.g. openai/gpt-4o, google/gemini-...).
    openrouter_model: str = "anthropic/claude-opus-4.1"

    # Anthropic (alternate, direct). Uses the native model id below.
    anthropic_api_key: str = ""
    ai_model: str = "claude-opus-4-8"

    # Local, self-hosted model via an OpenAI-compatible endpoint (Ollama/vLLM).
    # Keeps scan data in-house and needs NO external egress -- the right choice
    # when the network blocks the internet or intercepts TLS. Ollama's
    # OpenAI-compatible API lives under /v1; it ignores auth (a dummy key is sent).
    ollama_base_url: str = "http://localhost:11434/v1"
    ollama_model: str = "llama3.1:8b"
    ollama_api_key: str = ""

    # DeepSeek (OpenAI-compatible, cloud). Strong structured-JSON output -> a good
    # brain for the autonomous agent. Needs egress (honor SSL_CA_BUNDLE/proxy on
    # TLS-intercepting networks).
    deepseek_api_key: str = ""
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"

    ai_max_tokens: int = 4096
    ai_request_timeout_s: float = 60.0
    ai_max_retries: int = 3

    # AI correlator (attack-path narrative) latency controls. A large scan must not
    # trigger unbounded AI work: beyond ai_correlator_max_findings the AI narrative
    # is skipped (findings are STILL deterministically mapped to ATT&CK; only the
    # generated story is bounded). The call is also wall-clock bounded and can use a
    # smaller/faster model. All fail-soft: a skip/timeout never fails the scan.
    ai_correlator_max_findings: int = 60
    ai_correlator_timeout_seconds: float = 90.0
    ai_correlator_model: str = ""  # optional override; empty = the active provider's default

    # --- Outbound TLS / proxy (enterprise networking) -----------------------
    # For networks that intercept TLS (corporate proxy/AV) or require an egress
    # proxy. The correct fix for TLS inspection is a custom CA bundle -- NEVER
    # disabling verification. Proxies are honored by httpx (trust_env) and mirrored
    # into the process env by configure_networking() so the Go scanner tools use
    # them too.
    ssl_verify: bool = True          # dev-only override; MUST stay True in production
    ssl_ca_bundle: str = ""          # path to a custom CA bundle (PEM), e.g. corporate root
    http_proxy: str = ""
    https_proxy: str = ""
    no_proxy: str = ""

    # --- Scanner engine -----------------------------------------------------
    # Directory the Nuclei template set is baked into (set in Dockerfile.worker).
    # When set, the nuclei runner passes `-templates <dir>` so template discovery
    # never depends on the ambient $HOME at scan time. Empty = nuclei's own default.
    nuclei_templates_dir: str = ""

    # Target types the scanner can actually assess today. Scans on any other type
    # are rejected at creation -- never a "completed" scan that assessed nothing.
    # domain/ip_range are covered by the recon + nuclei toolchain; api /
    # cloud_account / repo need dedicated engines (roadmap) and stay gated until then.
    supported_target_types: list[str] = ["domain", "ip_range"]

    # --- SSRF / target safety (multi-tenant) --------------------------------
    # By default the scanner refuses to touch non-public addresses (loopback,
    # RFC1918, link-local, ULA, reserved, multicast) and cloud metadata endpoints,
    # at target creation AND at every DNS resolution (defends DNS rebinding).
    # Set scan_allow_private_targets=true ONLY for an on-prem/internal engagement,
    # and then only the exact CIDRs in scan_allowed_cidrs may be scanned. Cloud
    # metadata IPs stay blocked unless listed as an explicit host (/32 or /128) in
    # scan_allowed_cidrs. There is deliberately no blanket "disable SSRF" switch.
    scan_allow_private_targets: bool = False
    scan_allowed_cidrs: list[str] = []
    # M4.5 (G9): re-check DISCOVERED (derived) hosts against the target's authorized
    # scope before any active tool probes them. Out-of-scope / indeterminable-host
    # findings are recorded as observations but never actively scanned (fail closed).
    # Kill-switch only -- default True (secure); set False to restore prior behavior.
    scan_enforce_derived_scope: bool = True
    # EMERGENCY-ONLY acknowledgement to run in PRODUCTION with the control above
    # DISABLED. Left False, production refuses to start when derived-scope enforcement
    # is off (M4.6.1 / F2). Do NOT set this for convenience -- it turns off a security
    # control; document the incident/reason whenever it is used.
    scan_enforce_derived_scope_ack: bool = False
    # M4.6.4 (F1): explicit deny-list of discovered hosts that must NOT be actively
    # probed even when they fall within the target's name-based scope (e.g. a subdomain
    # CNAME'd to third-party infra). An entry matches an exact host or a parent suffix
    # (e.g. "cdn.example.com" excludes "assets.cdn.example.com" too). Empty by default
    # -> the name-based authorization model is unchanged. NARROWING-ONLY: an exclude can
    # never authorize a host the scope check would otherwise reject.
    scan_derived_scope_excludes: list[str] = []

    # --- Autonomous red-team agent -----------------------------------------
    # Deployment-wide safety ceiling the per-engagement RoE can restrict but never
    # exceed (see scanner_engine/safety.py). Default active_safe = recon + vuln
    # detection only; real exploitation additionally needs agent_exploitation_enabled
    # AND a per-engagement opt-in. agent_max_steps bounds the agentic loop.
    agent_safety_ceiling: str = "active_safe"     # passive | active_safe | intrusive
    agent_exploitation_enabled: bool = False      # deployment gate for INTRUSIVE actions
    agent_max_steps: int = 40                     # HARD ceiling on agentic loop steps (never bypassed)
    # M4.4.3 deterministic budget/stop controls. All default to a no-op so existing
    # behavior (bounded only by agent_max_steps) is unchanged until an operator opts
    # in. A budget may only STOP earlier -- never allow execution beyond agent_max_steps.
    agent_min_confidence: float = 0.0             # drop candidates below this confidence (0 = off)
    agent_time_budget_seconds: float = 0.0        # wall-clock budget across the loop (0 = off)
    agent_max_ai_calls: int = 0                   # cap on decide() calls (0 = off)
    agent_stall_limit: int = 0                    # stop after N consecutive tool runs with no new evidence (0 = off)
    agent_max_rounds: int = 1                     # recon<->exploitation re-entry rounds (M4.4.4; 1 = current)
    # Phase 1.2 -- orphan scan recovery. A scan stuck in 'running' past the timeout
    # (worker crashed/lost after the atomic claim) is safely marked 'failed' by a
    # periodic reaper. Timeout must exceed the longest legitimate scan to avoid false
    # positives. The reaper never re-dispatches, so it cannot cause duplicate execution.
    scan_orphan_recovery_enabled: bool = True         # master switch for the reaper
    scan_orphan_timeout_seconds: int = 7200           # 2h; 'running' older than this is an orphan
    scan_orphan_reaper_interval_seconds: int = 300    # reaper cadence (beat), default 5 min

    # Queued-scan relay: a scan row is durably committed 'queued' BEFORE it is dispatched to
    # Celery (create_scan), and celery_task_id is set only AFTER a successful dispatch. So a
    # 'queued' scan with celery_task_id IS NULL past this threshold was never delivered (the
    # DB+Redis dual-write's Redis side failed). The relay (run in the reaper task) re-dispatches
    # it; the atomic scan claim guarantees no double-execution. Conservative: only fires for
    # genuinely undelivered scans, never for scans already in flight (they have a task id).
    scan_queued_relay_enabled: bool = True
    scan_queued_relay_seconds: int = 300              # 5 min; 'queued' + no task id older than this

    # Phase 4.1 -- worker observability. The Celery worker runs scans (record_scan_result,
    # tool/AI/reaper/relay metrics), but /metrics is served by the API process only. This
    # starts a best-effort Prometheus endpoint IN the worker so those metrics are scrapable.
    # Best-effort: a bind failure never aborts worker startup. When PROMETHEUS_MULTIPROC_DIR
    # is set on the worker container, the endpoint aggregates all prefork children.
    worker_metrics_enabled: bool = True
    worker_metrics_port: int = 9100

    # Phase 1.5 -- graceful shutdown & worker reliability. Celery task time limits BOUND
    # a scan so a hung/very-long run can't block warm shutdown forever (which would force
    # a SIGKILL -> orphaned 'running' scan). The SOFT limit fires first and raises
    # SoftTimeLimitExceeded *inside* the task, so the orchestrator can mark the scan
    # 'failed' cleanly (reclaimable via the atomic claim); the HARD limit is the
    # last-resort force-kill and MUST be greater than the soft limit. Both stay BELOW the
    # orphan timeout so a self-terminated scan never has to wait on the reaper -- the
    # reaper remains the unchanged final fallback for a truly lost worker.
    celery_task_soft_time_limit_seconds: int = 3600   # 1h; raises SoftTimeLimitExceeded in-task
    celery_task_time_limit_seconds: int = 3900        # soft + 5min; hard SIGKILL backstop
    # Recycle a worker child after this many tasks so long-lived scanner subprocesses
    # (nmap/nuclei/katana) can't leak memory unbounded. 0 disables recycling.
    celery_worker_max_tasks_per_child: int = 50

    # Phase 1.6 -- backup & disaster recovery. Additive + OPT-IN: the scheduled backup
    # task is OFF by default (backup_enabled) so it never runs unexpectedly in dev/CI.
    # Every artifact is timestamped (never overwrites), checksummed, and verified.
    # Retention prunes by age but ALWAYS keeps >= backup_min_keep newest sets and NEVER
    # the newest -- a burst of failures can't erase the last good backup. Credentials come
    # from the existing DATABASE_URL / S3_* settings and are never logged.
    backup_enabled: bool = False                  # master switch for the scheduled backup
    backup_directory: str = "/srv/backups"        # root dir holding timestamped backup sets
    backup_interval_seconds: int = 86400          # scheduled cadence (beat), default daily
    backup_retention_days: int = 7                # prune sets older than N days
    backup_min_keep: int = 3                      # always keep >= this many newest sets
    backup_include_objects: bool = True           # also back up object storage (evidence+reports)
    backup_compression: bool = True               # gzip the object archive (db.dump is already -Fc compressed)
    backup_verification_enabled: bool = True      # verify each set after creation / before restore
    backup_pg_dump_cmd: str = "pg_dump"           # override to an absolute path / wrapper
    backup_pg_restore_cmd: str = "pg_restore"     # override to an absolute path / wrapper

    # --- Security edge ------------------------------------------------------
    # Hosts allowed in the Host header (TrustedHostMiddleware). "*" disables the
    # check (dev only). Set explicit hostnames in production.
    trusted_hosts: list[str] = ["*"]
    security_headers_enabled: bool = True
    enable_hsts: bool = False  # enable only when served over HTTPS
    # Off by default so local dev and the test suite are never throttled; turn on
    # in production (compose/env). Requires Redis (REDIS_URL); fails open if down.
    rate_limit_enabled: bool = False
    rate_limit_default: str = "300/minute"
    rate_limit_auth: str = "10/minute"
    rate_limit_ai: str = "30/minute"

    # --- Logging / observability -------------------------------------------
    log_level: str = "INFO"
    log_json: bool = True

    # How /metrics is protected. Secure by default:
    #   token         -- require the X-Metrics-Token header to equal METRICS_TOKEN
    #                    (Prometheus-friendly; pair with network restriction).
    #   authenticated -- require a valid bearer JWT.
    #   disabled      -- /metrics returns 404.
    #   public        -- open (development only).
    # In "token" mode with no METRICS_TOKEN set, access is denied (fail closed).
    metrics_mode: str = "token"
    metrics_token: str = ""

    # Browser origins allowed to call the API. The web app calls the API at
    # http://localhost:8000 regardless of where the page itself is served, so
    # every host the page can be opened from must be listed here or the browser
    # blocks the request ("Failed to fetch"): :3000 (next dev directly) and
    # :80/plain localhost (via nginx), plus the 127.0.0.1 equivalents.
    cors_allow_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost",
        "http://127.0.0.1:3000",
        "http://127.0.0.1",
    ]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def active_ai_api_key(self) -> str:
        """The API key for the currently selected provider ("" if unset). The
        local provider needs no real key, so it reports a sentinel -> ai_enabled."""
        return {
            "openrouter": self.openrouter_api_key,
            "anthropic": self.anthropic_api_key,
            "local": self.ollama_api_key or "local",
            "deepseek": self.deepseek_api_key,
        }.get(self.ai_provider, "")

    @property
    def active_ai_model(self) -> str:
        """The model id the selected provider will send."""
        return {
            "openrouter": self.openrouter_model,
            "anthropic": self.ai_model,
            "local": self.ollama_model,
            "deepseek": self.deepseek_model,
        }.get(self.ai_provider, self.openrouter_model)

    @property
    def httpx_verify(self):
        """Value for httpx `verify=`: a custom CA bundle path when configured (or
        the REQUESTS_CA_BUNDLE/SSL_CERT_FILE env fallback), else True. Returns
        False only when ssl_verify is explicitly disabled (development)."""
        if not self.ssl_verify:
            return False
        bundle = (
            self.ssl_ca_bundle
            or os.environ.get("REQUESTS_CA_BUNDLE")
            or os.environ.get("SSL_CERT_FILE")
        )
        return bundle if bundle else True

    @property
    def ai_enabled(self) -> bool:
        """True when the selected provider has a key -- the live-AI signal used by
        /ai/status. AI remaining disabled is not an error (graceful degradation)."""
        return bool(self.active_ai_api_key)

    def validate_production(self) -> None:
        """Fail fast at startup if production is running with insecure dev defaults.
        Called from the app lifespan. No-op outside production so local/dev/test are
        unaffected. Missing AI key is intentionally NOT fatal (AI degrades gracefully)."""
        if not self.is_production:
            return
        problems: list[str] = []
        if self.jwt_secret_key in _INSECURE_JWT_SECRETS or "change-me" in self.jwt_secret_key:
            problems.append("JWT_SECRET_KEY is a placeholder; set a strong random secret.")
        if self.s3_access_key == "minioadmin" or self.s3_secret_key == "minioadmin":
            problems.append("S3/MinIO credentials are the insecure defaults (minioadmin).")
        if "mbs:mbs@" in self.database_url:
            problems.append("DATABASE_URL uses the default dev credentials (mbs:mbs).")
        if "*" in self.cors_allow_origins:
            problems.append("CORS_ALLOW_ORIGINS must list explicit origins in production, not '*'.")
        if self.trusted_hosts == ["*"]:
            problems.append("TRUSTED_HOSTS must list explicit hostnames in production, not '*'.")
        if self.ai_provider not in ("openrouter", "anthropic", "local", "deepseek"):
            problems.append(f"AI_PROVIDER '{self.ai_provider}' is not a known provider.")
        if not self.ssl_verify:
            problems.append("SSL_VERIFY is disabled; never disable TLS verification in production.")
        if not self.rate_limit_enabled:
            problems.append("RATE_LIMIT_ENABLED must be true in production (unrestricted limits are unsafe).")
        if self.metrics_mode == "public":
            problems.append("METRICS_MODE must not be 'public' in production.")
        # M4.6.1 / F2: refuse to run in production with derived-target authorization
        # enforcement disabled (unless explicitly, emergency-acknowledged).
        from apps.api.core.startup_checks import derived_scope_problem

        scope_problem = derived_scope_problem(
            is_production=self.is_production,
            enforce=self.scan_enforce_derived_scope,
            ack=self.scan_enforce_derived_scope_ack,
        )
        if scope_problem:
            problems.append(scope_problem)
        if problems:
            raise RuntimeError(
                "Refusing to start in production with insecure configuration:\n  - "
                + "\n  - ".join(problems)
            )


def configure_networking(settings: "Settings | None" = None) -> None:
    """Mirror proxy / CA settings into the process environment so every outbound
    client honors them: httpx picks up HTTP(S)_PROXY via trust_env, and the Go
    scanner tools (subfinder/httpx/nuclei/...) read REQUESTS_CA_BUNDLE/SSL_CERT_FILE
    and the proxy vars too. Idempotent; explicit env always wins (setdefault)."""
    s = settings or get_settings()
    for var, val in (("HTTP_PROXY", s.http_proxy), ("HTTPS_PROXY", s.https_proxy), ("NO_PROXY", s.no_proxy)):
        if val:
            os.environ.setdefault(var, val)
            os.environ.setdefault(var.lower(), val)
    if s.ssl_ca_bundle:
        os.environ.setdefault("REQUESTS_CA_BUNDLE", s.ssl_ca_bundle)
        os.environ.setdefault("SSL_CERT_FILE", s.ssl_ca_bundle)


@lru_cache
def get_settings() -> Settings:
    # Secret loading order (first present wins): explicit env / Docker-K8s env ->
    # external backend (setdefault) -> <NAME>_FILE (Docker/K8s secret files). See
    # core/secrets.py. External backend is a no-op unless SECRETS_BACKEND is set.
    from apps.api.core.secrets import load_external_secrets

    load_external_secrets()
    _resolve_file_secrets()
    return Settings()
