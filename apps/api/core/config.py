import os
from functools import lru_cache
from urllib.parse import quote_plus

from dotenv import dotenv_values
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Flexible DATABASE_URL discovery (Phase 0 MySQL cutover). Some hosting platforms (Railway,
# various PaaS MySQL add-ons) inject connection details as discrete MYSQLHOST/MYSQL_USER/...
# -style vars instead of a single DATABASE_URL; a developer pointing the app at a database
# they created themselves (e.g. by hand in MySQL Workbench) is usually in the same position --
# they think in host/port/user/password/db name, not a URL. First-match-wins per field,
# checking the most platform-specific name first and falling back to the generic
# DB_* / DATABASE_* convention.
_DB_HOST_VARS = ("MYSQLHOST", "MYSQL_HOST", "DB_HOST", "DATABASE_HOST")
_DB_PORT_VARS = ("MYSQLPORT", "MYSQL_PORT", "DB_PORT", "DATABASE_PORT")
_DB_NAME_VARS = ("MYSQLDATABASE", "MYSQL_DATABASE", "DB_NAME", "DATABASE_NAME")
_DB_USER_VARS = ("MYSQLUSER", "MYSQL_USER", "DB_USER", "DATABASE_USER")
_DB_PASSWORD_VARS = ("MYSQLPASSWORD", "MYSQL_PASSWORD", "DB_PASSWORD", "DATABASE_PASSWORD")


def _dotenv_snapshot() -> dict[str, str]:
    """Parse the local .env file -- same relative path Settings() itself reads via
    `env_file=".env"` -- WITHOUT exporting it into os.environ. Needed because
    _resolve_database_url_from_parts() runs before Settings() exists, so (unlike Settings'
    own fields) it can only see values that were actually exported as shell/compose env vars
    -- not ones that only live in .env. That silently broke the discrete DB_HOST/DB_USER/...
    vars for anyone who, reasonably, just edited .env by hand and never `export`ed anything.
    dotenv_values() never raises for a missing file (returns {}); re-parsed per call rather
    than cached since this only runs a handful of times at process startup."""
    return {k: v for k, v in dotenv_values(".env").items() if v}


def _first_env(names: tuple[str, ...]) -> str | None:
    """Real environment variables win over .env file values for each name -- matches
    pydantic-settings' own precedence for env_file=".env", so DB_HOST/DB_USER/... behave
    identically whether they're exported by the shell/docker-compose or only ever written
    into .env."""
    dotenv = None
    for name in names:
        val = os.environ.get(name)
        if val:
            return val
        if dotenv is None:
            dotenv = _dotenv_snapshot()
        val = dotenv.get(name)
        if val:
            return val
    return None


def _resolve_database_url_from_parts() -> None:
    """Populate DATABASE_URL from discrete host/port/user/password/name env vars -- real env
    vars OR .env file entries, see _first_env() -- when it isn't already set that way. Never
    overwrites an explicit DATABASE_URL or a declared DATABASE_URL_FILE (that still wins via
    _resolve_file_secrets(), called after this one -- see the precedence note on
    get_settings()). If no host var is present at all there's nothing to compose, and
    Settings() falls through to its class default (local dev). Safe to call repeatedly
    (idempotent once DATABASE_URL is set)."""
    if _first_env(("DATABASE_URL",)) or _first_env(("DATABASE_URL_FILE",)):
        return
    host = _first_env(_DB_HOST_VARS)
    if not host:
        return
    port = _first_env(_DB_PORT_VARS) or "3306"
    name = _first_env(_DB_NAME_VARS) or "mbs"
    user = _first_env(_DB_USER_VARS) or "mbs"
    password = _first_env(_DB_PASSWORD_VARS) or ""
    auth = quote_plus(user) + (f":{quote_plus(password)}" if password else "")
    os.environ["DATABASE_URL"] = f"mysql+aiomysql://{auth}@{host}:{port}/{name}"


# Secrets that may be delivered via a `<NAME>_FILE` env var pointing at a file
# (Docker Secrets mount secrets at /run/secrets/*, Vault Agent can template to a
# file). Resolving these into the plain env var before Settings() is constructed
# keeps the rest of the app oblivious to *how* the secret arrived -- the
# Vault-ready seam without taking a Vault dependency now.
_FILE_BACKED_SECRETS = (
    "JWT_SECRET_KEY",
    "DATABASE_URL",
    # B3: once Redis requires a password the connection string carries it, so REDIS_URL is a
    # secret and travels the same way. Delivered as REDIS_URL_FILE in production; the plain
    # var stays the local-development path.
    "REDIS_URL",
    "S3_ACCESS_KEY",
    "S3_SECRET_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "DEEPSEEK_API_KEY",
    "METRICS_TOKEN",
    "MFA_ENCRYPTION_KEY",
    # MBS.SC: the scanner execution plane's ONE credential. File-backed like every other
    # secret so production can deliver it as a Docker secret
    # (SCANNER_WORKER_TOKEN_FILE=/run/secrets/scanner_worker_token) rather than as an
    # inline env value that would sit in `docker inspect` output.
    "SCANNER_WORKER_TOKEN",
    # DR-2 / DR-3: backup encryption key + off-site replication secret (same Vault/Docker
    # Secrets seam). Empty by default; only required when the matching feature is enabled.
    "BACKUP_ENCRYPTION_KEY",
    "BACKUP_OFFSITE_SECRET_KEY",
    # Email alerts (E1): SMTP password via the same *_FILE convention (SMTP_PASSWORD_FILE).
    "SMTP_PASSWORD",
)

# Placeholder / insecure defaults that must never survive into production.
_INSECURE_JWT_SECRETS = {"", "change-me-in-.env", "change-me-generate-a-real-secret"}


# Secret files that were declared via `<NAME>_FILE` but could not be read. Recorded here
# rather than raised, because resolution runs before Settings exists; validate_production()
# turns them into a startup failure so a mounted-but-unreadable secret can never be silently
# replaced by an inherited default. Rebuilt on every resolve() call (idempotent).
_UNREADABLE_FILE_SECRETS: list[str] = []

# F-05: environment names that count as a developer machine. Only here may
# DEV_AUTO_AUTHORIZE_TARGETS -- which disables the target-ownership authorization guardrail --
# be enabled. Anything not on this list (staging, prod, qa, a typo, a name nobody anticipated)
# is treated as a real deployment and refuses to start with the flag on. Keep this list SHORT:
# every entry added here is another environment allowed to scan without proof of authorization.
_LOCAL_ENVIRONMENTS: frozenset[str] = frozenset({"development", "dev", "local", "test", "testing"})

# F-06: AI providers that bill per token. Production must carry a spend cap when one of these
# is live. `local` (self-hosted Ollama) is absent deliberately -- it has no per-token cost, so
# requiring a dollar budget there would be noise. Adding a provider here without adding it to
# the pricing table would make its spend uncountable, so keep the two in step.
_METERED_AI_PROVIDERS: frozenset[str] = frozenset({"openrouter", "anthropic", "deepseek"})


def _resolve_file_secrets() -> None:
    """Resolve every `<NAME>_FILE` env var into `<NAME>`, with **the file winning**.

    PRECEDENCE (deliberate, and the reason this is not `if not os.environ.get(name)`):
    a declared `<NAME>_FILE` is an explicit statement that the secret is delivered by
    Docker Secrets / Vault, so it must beat whatever `<NAME>` happens to be inherited.
    The compose base file loads `env_file: ../.env` into every application service, and a
    compose overlay CANNOT unset an env_file-sourced variable -- so under the old
    "first value wins" rule a stale `.env` entry silently defeated the mounted secret and
    production ran on a development key with no signal. The file is the source of truth.

    Configuration that is NOT secret is untouched: only the `_FILE_BACKED_SECRETS` names
    participate, and only when the operator actually declared the matching `_FILE` var.

    Never raises -- an unreadable path is recorded in `_UNREADABLE_FILE_SECRETS` and
    surfaced by validate_production() instead, so the inherited value cannot quietly stand
    in for a secret the operator believed was mounted. Safe to call repeatedly.
    """
    _UNREADABLE_FILE_SECRETS.clear()
    for name in _FILE_BACKED_SECRETS:
        file_var = f"{name}_FILE"
        path = os.environ.get(file_var)
        if not path:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                os.environ[name] = fh.read().strip()
        except OSError:
            # Declared but unreadable: never fall back silently -- see validate_production().
            _UNREADABLE_FILE_SECRETS.append(file_var)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "MBS.SC API"
    api_v1_prefix: str = "/api/v1"
    environment: str = "development"

    database_url: str = "mysql+aiomysql://mbs:mbs@mysql:3306/mbs"
    # Phase 0 MySQL cutover pool tuning (see core/db.py for why pool_recycle matters on
    # MySQL specifically). 1800s (30min) is comfortably under the lowest wait_timeout
    # commonly seen on managed/shared MySQL tiers; override per-environment if needed.
    db_pool_recycle_seconds: int = 1800
    db_pool_size: int = 10
    db_pool_max_overflow: int = 5
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

    # --- F-08: refresh token delivered as an HttpOnly cookie ---------------------------------
    # The refresh token used to be returned in the JSON body and parked in localStorage, where
    # any XSS could read it and mint access tokens for the full 7-day refresh lifetime. It is
    # now set as an HttpOnly cookie that JavaScript cannot read at all.
    #
    # SameSite=strict is the CSRF control: /auth/refresh and /auth/logout are cookie-
    # authenticated, and a strict cookie is simply not attached to any cross-site request, so a
    # third-party page cannot drive them. This works because the browser reaches the API
    # SAME-ORIGIN through nginx (/api/v1/... -> api:8000), which is also why the frontend now
    # uses a relative API base instead of http://localhost:8000.
    #
    # `secure` defaults to False so plain-http local development keeps working (a Secure cookie
    # is dropped over http). validate_production() FORCES it true in production -- see there.
    refresh_cookie_name: str = "mbs_refresh"
    refresh_cookie_secure: bool = False
    refresh_cookie_samesite: str = "strict"
    # Scoped to the auth routes only: the cookie is never attached to ordinary API calls, so it
    # cannot leak through unrelated endpoints or be logged by them.
    refresh_cookie_path: str = "/api/v1/auth"

    # MFA (Sprint 1 foundation). mfa_encryption_key is the master secret used to derive a Fernet
    # key that encrypts each user's TOTP secret at rest (mfa_secret_encrypted); it supports the
    # <NAME>_FILE convention via _FILE_BACKED_SECRETS (Docker Secrets / Vault). Empty by default
    # -- MFA helpers raise a clear error if used unconfigured. No login behavior depends on these
    # yet (foundation only). mfa_challenge_ttl_seconds bounds the interim MFA-challenge token.
    mfa_issuer: str = "MBS.PT"
    mfa_challenge_ttl_seconds: int = 300
    mfa_encryption_key: str = ""
    # Per-user MFA brute-force protection (Step 3, Redis-backed, independent of IP rate limiting).
    mfa_max_attempts: int = 5           # failed second-factor attempts before a temporary lockout
    mfa_lockout_seconds: int = 900      # lockout window (15 min); the failure counter's TTL

    # --- AI Agent Service ---------------------------------------------------
    # Which provider the AI layer uses. Business logic never reads this -- only
    # the provider factory (apps/api/ai_agent/providers/factory.py) does. All
    # providers conform to the SupportsComplete protocol, so switching is a
    # config change, not a code change.
    ai_provider: str = "openrouter"  # openrouter | anthropic | local | deepseek

    # AI-2.1 -- provider fallback. Ordered list of SECONDARY providers tried, in order, ONLY when
    # the current provider hits an availability failure (429/402/5xx/timeout/connection). Default
    # [] = OFF (single-provider behavior, unchanged). The primary (ai_provider) is always first;
    # duplicates and a self-reference are dropped, and a fallback with no configured key is
    # skipped at build time. e.g. AI_FALLBACK_PROVIDERS='["anthropic","deepseek"]'.
    ai_fallback_providers: list[str] = []

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

    # AI-2.2B-1 -- config-driven pricing overrides for cost ESTIMATION. Maps a model-id substring
    # to [in_per_1k_usd, out_per_1k_usd], so rates can be corrected without a deploy. Empty {} =
    # unchanged (built-in table + conservative default). Applies to FUTURE calls only -- historical
    # ai_usage rows keep the cost computed at the time of the call.
    # e.g. AI_PRICING_OVERRIDES='{"deepseek":[0.00027,0.0011],"gpt-4o":[0.0025,0.01]}'.
    ai_pricing_overrides: dict[str, list[float]] = {}

    # AI-2.2A -- AI cost budget enforcement. Additive + default OFF: with ai_budget_enforce=False
    # (or ai_daily_budget_usd<=0) nothing is ever blocked. When enabled, a per-workspace rolling
    # DAILY estimated spend is tracked in Redis; once it reaches the cap, further AI calls for that
    # workspace are blocked (AIBudgetExceededError) and degrade through the EXISTING contract
    # (assistant -> 503, agent -> finish). Redis failures fail OPEN (never block AI on an outage).
    ai_budget_enforce: bool = False
    ai_daily_budget_usd: float = 0.0

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

    # Wordlist the ffuf runner uses for directory/file content discovery (set in
    # Dockerfile.worker). Empty = ffuf's own bundled default.
    ffuf_wordlist_path: str = ""

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
    # MBS.SC: these two remain the OUTER SAFETY BOUNDARY and nothing more. Since the
    # per-scan policy landed (scanner_engine/net_policy.py), turning this on grants NOTHING
    # by itself -- it only stops forbidding, and a scan still needs its own persisted
    # workspace -> site -> CIDR authorization. Leaving it False keeps private scanning off
    # entirely, whatever any tenant has configured.
    scan_allow_private_targets: bool = False
    scan_allowed_cidrs: list[str] = []
    # MBS.SC Phase 13 -- EMERGENCY CONTROL. Set true to stop ALL private scanning platform
    # wide, immediately, without touching any site or worker row. Enforced by the
    # scanner-manager (control-plane side), so it takes effect even for a scanner host that
    # is compromised, unreachable, or ignoring its own configuration -- an emergency
    # control that depended on reaching the thing you are trying to cut off would be
    # useless exactly when it is needed.
    private_scanning_emergency_disable: bool = False
    # MBS.SC: marks this process as the scanner EXECUTION plane. It changes which
    # production invariants are enforced (see validate_production) and switches on the
    # credential guard in celery_app/startup_security.py. Never set it on the API or on a
    # control-plane worker -- those legitimately hold the credentials it forbids.
    scanner_execution_plane: bool = False
    # The one control-plane endpoint the execution plane may talk to.
    scanner_manager_url: str = ""
    scanner_worker_id: str = ""
    # The worker's own bootstrap credential. Authorizes nothing beyond this ONE worker's
    # authorized pool/site -- the manager re-derives every permission from the worker's
    # persisted row, so holding this is not equivalent to holding a control-plane secret.
    scanner_worker_token: str = ""
    scanner_pool_id: str = "public-default"
    scanner_site_id: str = ""
    # The WireGuard interface a PRIVATE worker probes for tunnel health. Configuration, not
    # a secret: the interface name says nothing about the customer, and the probe is
    # read-only.
    scanner_wireguard_interface: str = "wg0"
    # Path to the worker's OWN WireGuard private key, mounted as a Docker/Vault secret.
    # A FILE, not a value: an env var appears in `docker inspect`, in crash dumps, and in
    # every child process's environment. The key is generated INSIDE the private worker
    # (`wg genkey`) and never leaves it -- the control plane stores only the public half.
    scanner_wireguard_private_key_file: str = ""
    # The worker's address on the tunnel (e.g. 10.99.0.2/32). Assigned by the operator when
    # the site is provisioned; not secret.
    scanner_wireguard_address: str = ""
    # PHASE 8 -- how old a WireGuard handshake may be before the tunnel counts as dead and
    # private scanning is refused. WireGuard rekeys roughly every 120s while a session is
    # carrying traffic, so 180s is ~1.5 rekey intervals: long enough that a momentarily idle
    # tunnel is not falsely condemned, short enough that a genuinely dead peer is caught in
    # minutes rather than hours. Raise it only for a link with known long idle gaps, and
    # understand the trade: every extra second is a second a dead tunnel still looks alive.
    scanner_wireguard_max_handshake_age_s: int = 180
    # PHASE 8 -- tunnel MTU. 1420 is WireGuard's own default for IPv4-over-IPv4 on a 1500-byte
    # path (1500 - 20 IPv4 - 8 UDP - 32 WireGuard + Poly1305 overhead = 1440; wg uses 1420 to
    # leave headroom for IPv6 and common encapsulation). It is set EXPLICITLY rather than
    # inherited so the value is visible and auditable, and so a site behind PPPoE/a nested
    # tunnel (typically 1412 or lower) can be corrected without a code change.
    #
    # NOT a security control by itself: a wrong MTU costs reachability (black-holed large
    # packets), never isolation -- routes and AllowedIPs are what confine traffic, and a
    # fragmented or dropped packet cannot leave the authorized CIDR.
    scanner_wireguard_mtu: int = 1420

    # --- DEDICATED VPN EGRESS (public scanner traffic) -----------------------
    # A SEPARATE tunnel from the per-site WireGuard above, on a separate worker, with its
    # own interface, its own routing table and its own firewall. See
    # scanner_engine/vpn_egress.py for why the two are deliberately disjoint code paths.
    #
    # EXPLICIT MODE, never inferred. The private/public distinction is already carried by
    # `scanner_site_id`, and it would have been possible to infer "public + a key file
    # present => VPN". That inference is exactly the wrong failure mode: a worker whose
    # secret failed to mount would silently become a DIRECT worker and scan from the
    # platform's own address while looking correct. Declaring the mode means a
    # misconfigured VPN worker fails to start instead.
    #   direct -- ordinary public worker, egress via the host's own path (the default,
    #             unchanged behaviour for every existing deployment)
    #   vpn    -- all public target traffic leaves via the dedicated VPN tunnel
    scanner_egress_mode: str = "direct"
    # The dedicated egress interface. NOT `wg0`: a site worker's interface is wg0, and
    # identical names would make logs and operator commands ambiguous.
    scanner_vpn_egress_interface: str = "wg-egress"
    # PLATFORM secret, delivered as a FILE. Never an env value and never in .env.scanner --
    # that file is shared with tenant site workers, and this is a platform credential.
    scanner_vpn_egress_private_key_file: str = ""
    # Provider peer + this peer's assigned address. Not secrets.
    scanner_vpn_egress_peer_public_key: str = ""
    scanner_vpn_egress_endpoint_host: str = ""
    scanner_vpn_egress_endpoint_port: int = 51820
    scanner_vpn_egress_address: str = ""
    # Dedicated routing table + fwmark. Defaults match vpn_egress.py; configurable only so
    # a deployment with a conflicting table can move it.
    scanner_vpn_egress_table: int = 51820
    scanner_vpn_egress_fwmark: int = 0x51820
    scanner_vpn_egress_mtu: int = 1420
    scanner_vpn_egress_max_handshake_age_s: int = 180
    # EXIT-IP VERIFICATION. Tunnel-up plus a handshake proves the tunnel lives; it does not
    # prove traffic USES it. This URL is fetched over the worker's real egress path, so the
    # answer is evidence of where traffic actually leaves from.
    scanner_vpn_egress_exit_ip_url: str = "https://api.ipify.org"
    # Pin the provider's exit IP when it is stable. Empty still catches the common failure
    # (traffic never entered the tunnel) via `forbidden_exit_ips` below.
    scanner_vpn_egress_expected_exit_ip: str = ""
    # The platform's OWN direct egress address(es), comma-separated. Observing one of these
    # as the exit IP is positive proof the VPN was bypassed.
    scanner_vpn_egress_forbidden_exit_ips: str = ""
    # The dispatch-plane CIDR(s) the kill-switch permits directly, so the manager stays
    # reachable. Narrow by design: a blanket RFC1918 exception would re-open exactly the
    # private reachability an egress worker must not have.
    scanner_vpn_egress_dispatch_cidrs: str = ""
    # How often a RUNNING scan re-verifies the egress path. Without this a tunnel that dies
    # mid-scan would let the remaining tools continue over direct egress.
    scanner_vpn_egress_recheck_seconds: int = 60

    # CONTROL-PLANE side of the egress model. The pool id(s) whose workers are VPN-egress
    # workers, comma-separated. Read by the MANAGER to derive a worker's egress mode from
    # its persisted `pool_id` -- which is why no new database column is required: pool
    # membership is already persisted, operator-controlled and enforced at every
    # authorization boundary. See scanner_workers/service.worker_egress_mode.
    vpn_egress_pools: str = "public-vpn-egress"

    @property
    def vpn_egress_pool_list(self) -> list[str]:
        raw = self.vpn_egress_pools or ""
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def vpn_egress_enabled(self) -> bool:
        return (self.scanner_egress_mode or "direct").strip().lower() == "vpn"

    @property
    def vpn_egress_forbidden_exit_ip_list(self) -> list[str]:
        raw = self.scanner_vpn_egress_forbidden_exit_ips or ""
        return [p.strip() for p in raw.split(",") if p.strip()]

    @property
    def vpn_egress_dispatch_cidr_list(self) -> list[str]:
        raw = self.scanner_vpn_egress_dispatch_cidrs or ""
        return [p.strip() for p in raw.split(",") if p.strip()]

    # M4.5 (G9): re-check DISCOVERED (derived) hosts against the target's authorized
    # scope before any active tool probes them. Out-of-scope / indeterminable-host
    # findings are recorded as observations but never actively scanned (fail closed).
    # Kill-switch only -- default True (secure); set False to restore prior behavior.
    scan_enforce_derived_scope: bool = True
    # Screenshot evidence: capture the affected page for non-info web findings during a scan,
    # so the Technical Report can show it. OFF by default -- it requires Playwright + Chromium
    # in the WORKER image, so a deployment without them must not try (and fail) on every
    # finding. Capture is best effort and fully gated by the existing scope/SSRF guards; see
    # scanner_engine/screenshot.py.
    screenshot_evidence_enabled: bool = False
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
    # LIVENESS-BASED orphan detection. The reaper keys on the executor's heartbeat
    # (scans.last_heartbeat_at, stamped ~every TOOL_PROGRESS_INTERVAL_SECONDS while a tool
    # runs), NOT on total runtime -- so a legitimately long scan (a 3-5h nuclei/ffuf run is
    # normal on a large target) is never reaped while it is alive, and a scan whose worker
    # was SIGKILLed/OOM-killed is recovered in minutes instead of waiting out a fixed
    # wall-clock timeout. This is strictly better on BOTH axes than the previous
    # `started_at`-age rule, which had to trade one against the other.
    #
    # 900s = 15 min, i.e. ~30 consecutive missed 30s heartbeats. Chosen well above any
    # plausible transient stall (a slow heartbeat UPDATE, a GC pause, brief DB contention)
    # so a live scan is never falsely reaped, while still recovering a dead worker far
    # faster than the old 2h rule. This is NOT an execution limit: it caps how long a
    # scan may be SILENT, never how long it may RUN.
    scan_stale_heartbeat_seconds: int = 900
    # Retained ONLY as the fallback for a scan that has never stamped a heartbeat (claimed
    # but died before its first tick, or started by a pre-heartbeat build): the reaper
    # COALESCEs last_heartbeat_at -> started_at, so this bounds that no-heartbeat case
    # alone. A heartbeating scan is governed by scan_stale_heartbeat_seconds above and is
    # NOT subject to this value at any runtime.
    scan_orphan_timeout_seconds: int = 7200           # 2h; no-heartbeat fallback only
    scan_orphan_reaper_interval_seconds: int = 300    # reaper cadence (beat), default 5 min

    # TOOL-RUN orphan reconciliation. Distinct from both reapers above, which recover a
    # SCAN row: this one repairs `tool_runs` left in 'running' underneath a scan that has
    # already reached a terminal status -- a lifecycle state that is, by definition,
    # impossible to leave legitimately (nothing will ever report that tool's result again,
    # because its scan is over).
    #
    # Incident 615d0e0b produced exactly one such row: the manager's asset INSERT failed,
    # its transaction rolled back the ToolRun status write with it, and katana stayed
    # 'running' for good -- the UI rendered a live-ticking timer for a process that had
    # already been OOM-killed. The transactional fix prevents NEW ones; this reconciles the
    # rows already stranded, and any produced by a route not yet foreseen.
    #
    # GRACE PERIOD, not an immediate sweep: scan finalization and the tool's own result
    # submission are separate writes, so a tool result legitimately in flight can arrive
    # microseconds AFTER its scan goes terminal. Reconciling instantly would race that
    # write and mark a tool failed that was about to report success. 300s is far longer
    # than that window while still repairing a stranded row within one reaper cycle or two.
    toolrun_reconcile_enabled: bool = True
    toolrun_reconcile_grace_seconds: int = 300

    # MBS.SC PHASE 8 (P8-F) -- WORKER-level stale reaper. Distinct from the SCAN-level
    # reaper above: that one recovers a dead scan, this one stops handing NEW work to a
    # worker that has gone silent. Before it existed, `last_seen_at` was written by every
    # heartbeat and consulted by nothing, so a worker silent for 42 minutes still leased
    # successfully (verified live).
    #
    # 600s is deliberately CONSERVATIVE and sits well above the two cadences that matter:
    # the idle heartbeat is 30s (lease_loop.BackoffPolicy.heartbeat_seconds) and the
    # existing MbsScannerWorkerHeartbeatStale alert fires at 300s. So a worker must miss
    # ~20 consecutive beats -- and be alerted on for ~5 minutes first -- before it is
    # suspended. That ordering is intentional: an operator sees the alert before the
    # platform acts, and a transient manager blip cannot turn a monitoring wobble into a
    # scanning outage. The transition is to `suspended`, which is REVERSIBLE.
    worker_stale_after_seconds: int = 600
    # Sweep cadence. Reuses the SCAN reaper's 300s so the two liveness sweeps tick together
    # and the platform has one recovery rhythm rather than two competing ones. At 300s a
    # stale worker is suspended within 600-900s of its last beat.
    worker_stale_reaper_interval_seconds: int = 300
    # P1.1 -- beat-liveness heartbeat. A tiny periodic task stamps a Redis timestamp each tick so a
    # stalled beat scheduler (or a down worker-default draining the default queue) is alertable via
    # mbs_beat_age_seconds -> MbsBeatStalled. Always scheduled; additive, cheap, low-cardinality.
    beat_heartbeat_interval_seconds: int = 60         # heartbeat cadence (beat), default 60s

    # Queued-scan relay: a scan row is durably committed 'queued' BEFORE it is dispatched to
    # Celery (create_scan), and celery_task_id is set only AFTER a successful dispatch. So a
    # 'queued' scan with celery_task_id IS NULL past this threshold was never delivered (the
    # DB+Redis dual-write's Redis side failed). The relay (run in the reaper task) re-dispatches
    # it; the atomic scan claim guarantees no double-execution. Conservative: only fires for
    # genuinely undelivered scans, never for scans already in flight (they have a task id).
    scan_queued_relay_enabled: bool = True
    scan_queued_relay_seconds: int = 300              # 5 min; 'queued' + no task id older than this

    # WHICH MECHANISM DISPATCHES A SCAN. False (the default) = the MBS.SC LEASE model: the
    # scan row itself is the queue, and a worker claims it through POST /v1/lease ->
    # _claim_scan. True = the legacy CONTROL-PLANE Celery path, for a deployment that still
    # runs an executor consuming `scans.public` / `scans.private.<site>`.
    #
    # DEFAULT OFF, AND THAT DEFAULT IS THE FIX. `create_scan` used to enqueue
    # unconditionally, but under the deployed lease architecture nothing consumes those
    # queues -- the scan worker is off `mbs-core`, cannot reach Redis, and runs
    # `scanner_worker.main` rather than `celery worker`. Every scan therefore produced an
    # undelivered message (measured: 110 in `scans.public`) AND set `celery_task_id`, which
    # is precisely the field `_relay_queued()` uses to decide a scan was already dispatched.
    # A successful-but-unconsumable enqueue thus disqualified the scan from its own safety
    # net, leaving it `queued` forever.
    #
    # ENABLE THIS ONLY IF A CONSUMER ACTUALLY EXISTS for the scan queues. Turning it on
    # without one reintroduces exactly that failure, which is why the default is the safe
    # direction and why test_queue_topology asserts the two stay consistent.
    celery_scan_dispatch_enabled: bool = False

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
    # NOTE: these are the limits for EVERY OTHER task. `scans.run_scan` is exempt -- see
    # celery_app/worker.py's task_annotations and the two settings below.
    celery_task_soft_time_limit_seconds: int = 3600   # 1h; raises SoftTimeLimitExceeded in-task
    celery_task_time_limit_seconds: int = 3900        # soft + 5min; hard SIGKILL backstop
    # SCAN EXECUTION IS NOT WALL-CLOCK BOUNDED. A scan's legitimate duration is a function of
    # the target (subdomain/host/port/URL counts, crawl depth, wordlist and template counts,
    # rate limiting), not of the clock: 3-5 hours is normal on a large scope. The global
    # limits above used to apply to `scans.run_scan` too, which killed every such scan at 1h
    # and marked it 'failed' purely for existing too long -- a correctness bug, not a
    # safeguard. Scans are therefore exempted (None = no limit) and their liveness is
    # governed by scan_stale_heartbeat_seconds instead, which detects a genuinely DEAD
    # executor without ever penalising a healthy slow one.
    #
    # Set both to a positive number ONLY to deliberately re-impose a hard ceiling on scan
    # runtime; leave at 0 for the intended behavior. Whatever is set here must stay BELOW
    # celery_broker_visibility_timeout_seconds (asserted in the worker tests).
    celery_scan_task_soft_time_limit_seconds: int = 0   # 0 = no soft limit for scans.run_scan
    celery_scan_task_time_limit_seconds: int = 0        # 0 = no hard limit for scans.run_scan
    # Redis broker visibility timeout, now set EXPLICITLY rather than derived from the hard
    # task limit (which no longer exists for scans). Under acks_late an in-flight scan's
    # message sits in the broker's unacked set; if this elapses first, Redis restores and
    # REDELIVERS that message while the original worker is still scanning. The atomic claim
    # stops the redelivery executing, but it consumes the one message that gave the scan its
    # acks_late redelivery safety net -- so this must comfortably exceed the longest scan we
    # intend to support. 21600s = 6h: the 5h upper bound of a legitimately long scan plus a
    # ~20% margin. Raise it (not the scan limits) if scans longer than that become normal.
    celery_broker_visibility_timeout_seconds: int = 21600
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
    backup_compression: bool = True               # gzip the object archive (db.sql is plain-text, uncompressed)
    backup_verification_enabled: bool = True      # verify each set after creation / before restore
    # Phase 0 MySQL cutover: backup_pg_dump_cmd/backup_pg_restore_cmd (pg_dump/pg_restore) ->
    # backup_mysqldump_cmd/backup_mysql_cmd (mysqldump / the mysql client, which also performs
    # restore -- MySQL's standard tooling has no separate "mysqlrestore" binary).
    backup_mysqldump_cmd: str = "mysqldump"       # override to an absolute path / wrapper
    backup_mysql_cmd: str = "mysql"               # override to an absolute path / wrapper
    # TLS mode for the mysqldump/mysql CLIENTS specifically (NOT the app's own aiomysql engine,
    # which negotiates its own TLS independently -- see core/db.py). Three accepted values:
    #
    #   "required"        (default) -- connect over TLS, but do NOT verify the server's
    #                      certificate chain or hostname. The traffic is still ENCRYPTED; what
    #                      is skipped is proving the server's identity.
    #   "verify_identity" -- full verification: the chain must validate against backup_mysql_
    #                      ssl_ca AND the certificate's CN/SAN must match the connection host.
    #                      Requires certificates provisioned for the DB's actual hostname.
    #   "disabled"        -- no TLS at all. Only for a local socket / already-encrypted tunnel.
    #
    # Why "required" is the DEFAULT rather than "verify_identity": the mysql:8.0 image
    # auto-generates a SELF-SIGNED CA on first start, and the certificate it issues carries
    # CN="MySQL_Server_<version>_Auto_Generated_Server_Certificate" -- a name that can never
    # match the host it's reached by ("mysql" on the compose network). Both failures were
    # reproduced against this project's own running stack: with no TLS option set at all,
    # MariaDB's mysqldump (the client Debian's default-mysql-client ships, and the one baked
    # into infra/docker/Dockerfile.worker) verifies BY DEFAULT and aborts with
    #   'TLS/SSL error: self-signed certificate in certificate chain' (exit 2, EMPTY dump);
    # and pointing ssl-ca at the server's real auto-generated ca.pem merely moves the failure to
    #   'TLS/SSL error: Hostname verification failed'.
    # That is why DR backups silently produced nothing before this setting existed. Note the
    # asymmetry that hid it: Oracle's own mysql client does NOT verify by default, so the same
    # command "works" on a machine with mysql-client instead of mariadb-client installed.
    #
    # Operators who provision real certificates for the database host SHOULD set this to
    # "verify_identity" and point backup_mysql_ssl_ca at the issuing CA -- the code path is
    # implemented and takes precedence; nothing needs to change but these two values.
    backup_mysql_ssl_mode: str = "required"
    backup_mysql_ssl_ca: str = ""                 # PEM path; required by "verify_identity"
    # Phase F5: per-task Celery time limits so a large backup isn't cut off by the scan-tuned
    # global limit. soft raises SoftTimeLimitExceeded in-task (graceful log + F4 metric); hard is
    # the SIGKILL backstop and MUST exceed soft (enforced at wiring time).
    backup_task_soft_time_limit_seconds: int = 7200   # 2h
    backup_task_time_limit_seconds: int = 7800        # soft + 10min

    # DR-2 -- backup encryption at rest. Additive + OPT-IN (default OFF -> unencrypted sets,
    # identical to prior behavior). When enabled, each set's db.sql + objects archive are
    # encrypted in place with AES-256-GCM; the key is derived from BACKUP_ENCRYPTION_KEY
    # (supports the <NAME>_FILE convention). verify/restore transparently decrypt; a wrong key
    # fails closed (authentication tag mismatch). Existing unencrypted sets stay readable.
    backup_encryption_enabled: bool = False
    backup_encryption_key: str = ""
    # DR-3 -- off-site replication. Provider-agnostic: after a verified set, replicate it to an
    # off-host target. Default OFF. `local` copies to a mounted/off-host directory; `s3` uploads
    # to ANY S3-compatible endpoint (AWS, MinIO, Wasabi, ...) -- never hard-coded to one cloud.
    backup_offsite_enabled: bool = False
    backup_offsite_provider: str = "local"        # local | s3
    backup_offsite_dir: str = ""                  # local provider: destination base directory
    backup_offsite_bucket: str = ""               # s3 provider: destination bucket
    backup_offsite_prefix: str = "mbs-backups"    # s3 provider: key prefix
    backup_offsite_endpoint_url: str = ""         # s3 provider: custom endpoint (blank -> AWS default)
    backup_offsite_access_key: str = ""           # s3 provider: falls back to S3_ACCESS_KEY if blank
    backup_offsite_secret_key: str = ""           # s3 provider: falls back to S3_SECRET_KEY if blank
    backup_offsite_region: str = "us-east-1"
    # DR-4 -- manual DR drill scratch database. run_drill restores the latest verified set here
    # and refuses to touch the live DATABASE_URL. Empty -> a target must be passed on the CLI.
    backup_drill_database_url: str = ""

    # Email Alert System (E1..E5). Additive + default OFF: with email_enabled=False nothing is
    # ever sent (the dispatcher and Celery task short-circuit). Delivery is ALWAYS async (the
    # scan/backup paths only enqueue), so a slow/broken SMTP server never affects a scan. The
    # SMTP password uses the <NAME>_FILE convention (SMTP_PASSWORD_FILE) via _FILE_BACKED_SECRETS.
    email_enabled: bool = False
    email_provider: str = "smtp"                  # smtp (only provider today; abstraction allows more)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True                     # STARTTLS after connect
    smtp_timeout_seconds: int = 15
    email_from_address: str = ""
    # System-level alerts (backup/DLQ failures) have no workspace context -> sent to these admins.
    email_admin_recipients: list[str] = []
    # Dedup window: identical (category, workspace, subject) alerts inside this window are
    # collapsed to one email, preventing storms from a flapping failure.
    email_dedup_window_seconds: int = 300
    email_max_retries: int = 3                     # Celery retries for transient SMTP faults
    email_task_soft_time_limit_seconds: int = 25
    email_task_time_limit_seconds: int = 40        # > soft; hard SIGKILL backstop

    # Phase 5.2 -- retention purge FOUNDATION. Additive + DOUBLE-GATED OFF: nothing is ever
    # deleted unless retention_enabled is flipped true AND retention_dry_run is set false.
    # Ships enabled=False + dry_run=True so any manual/scheduled run only ever PLANS (logs +
    # meters what it *would* delete) and touches no data. batch_size/min_keep bound the blast
    # radius the same way backup retention does. Windows are in DAYS (a scan is measured from
    # completion, evidence from its scan, the rest from created_at). The actual eligibility
    # query + deletion is Phase 5.3 -- this block only configures the foundation.
    retention_enabled: bool = False               # master switch; False -> purge is a no-op
    retention_dry_run: bool = True                # True -> plan only, never delete (belt + suspenders)
    retention_interval_seconds: int = 86400       # Phase 5.3.3 beat cadence (default daily); only ticks when enabled
    retention_batch_size: int = 500               # max rows/objects touched per resource per run
    retention_min_keep: int = 10                  # always keep >= this many newest per resource
    retention_evidence_days: int = 90             # raw scan evidence objects + rows
    retention_scan_days: int = 180                # scan records + non-finding subtree
    retention_ai_usage_days: int = 180            # AI cost/usage log
    retention_report_days: int = 365              # generated reports (rows + PDFs)
    retention_refresh_token_grace_days: int = 7   # expired refresh tokens, N days past expiry
    retention_notification_days: int = 90         # in-app notifications
    retention_audit_days: int = 730               # audit events (long compliance window)
    # Remediation/assessment retention. remediation_events is the only one of the new tables
    # that grows without bound (one row per workflow action, forever), so it gets its own
    # window. The workflow ITEMS themselves are not aged off by time -- an item is deleted
    # with its project, and purging live remediation work on a clock would destroy the record
    # of outstanding obligations.
    retention_remediation_event_days: int = 730   # remediation workflow history (matches audit)
    # ISSUED assessments are CLIENT-FACING DELIVERABLES -- a client may ask for last year's
    # report years later -- so they get the longest window of anything here, deliberately
    # longer than the 365-day report window that ages off the rendered PDF.
    retention_risk_assessment_days: int = 1825    # issued client assessments (5 years)
    # Risk-acceptance expiry sweep cadence. Hourly: expiries are set in days/months, so a
    # sub-hour lag is immaterial, while an hourly per-tenant status flip is negligible load.
    risk_acceptance_expiry_interval_seconds: int = 3600
    # Phase F5: per-task Celery time limits (independent of the scan-tuned global limit). soft <
    # hard enforced at wiring time; a soft timeout is handled gracefully (per-workspace commits
    # mean partial progress is kept and the next run resumes).
    retention_task_soft_time_limit_seconds: int = 5400   # 90min
    retention_task_time_limit_seconds: int = 6000        # soft + 10min

    # --- Local development convenience --------------------------------------
    # DEV-ONLY escape hatch for the authorization-scope guardrail (apps/api/modules/
    # authorization_scope): a real engagement must submit ownership proof for a target and
    # have an owner separately verify it (and opt in to active testing) before ANY scan --
    # that flow is unchanged and still the default. Flipping this on auto-authorizes every
    # target (verified=True, active_testing_allowed=True) the moment a scan is requested,
    # so a developer iterating against infrastructure they already own doesn't have to
    # click through the manual submit-proof + owner-verify UI steps on every fresh dev
    # database. NEVER set this for a real engagement -- F-05: startup is refused with this
    # enabled unless ENVIRONMENT is an explicitly LOCAL name (_LOCAL_ENVIRONMENTS), not merely
    # "not production" (see validate_production).
    dev_auto_authorize_targets: bool = False

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
    # How many TRUSTED reverse proxies sit in front of the app. X-Forwarded-For is
    # client-controllable, so it is only honored when this is > 0, and then the client's
    # own hop is read as the Nth entry FROM THE RIGHT (leftmost entries are attacker-
    # spoofable). 0 (default) = ignore XFF entirely and use the direct peer, so a spoofed
    # header can never mint fresh rate-limit buckets. Set to the real proxy-hop count in
    # production (e.g. 1 behind a single nginx). Negative values are meaningless here, so the
    # field refuses them outright rather than silently behaving as 0. Production must DECLARE
    # this value -- see validate_production().
    trusted_proxy_count: int = Field(0, ge=0)

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
    def is_local_environment(self) -> bool:
        """True only for an environment name explicitly recognised as a developer machine.

        F-05: deliberately an ALLOW-list, not `not is_production`. A deny-list answers "is this
        the one name we thought of?", which silently treats staging/prod/qa/typos as safe; an
        allow-list answers "is this provably local?", so an unrecognised name fails closed.
        Whitespace and case are normalised because ENVIRONMENT comes from a hand-edited .env."""
        return self.environment.strip().lower() in _LOCAL_ENVIRONMENTS

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
        Called from the app lifespan. Mostly a no-op outside production so local/dev/test are
        unaffected -- the ONE exception is the F-05 guardrail check below, which deliberately
        runs in EVERY environment. Missing AI key is intentionally NOT fatal (AI degrades
        gracefully)."""
        # --- F-05: the scan-authorization guardrail must not be silently disableable -------
        # DEV_AUTO_AUTHORIZE_TARGETS short-circuits require_verified_target() entirely: with it
        # on, MBS will actively scan any target the operator names, with no proof of ownership
        # and overriding even an explicitly-unverified scope. That is the control that keeps
        # this product's scanning lawful, so "it is only blocked in production" was too weak a
        # guarantee -- `is_production` is a free-text comparison against the single literal
        # "production", so ENVIRONMENT=staging / prod / qa (or a typo like " production")
        # all sailed past the old check with the bypass fully active. Verified before the fix:
        # every one of those booted successfully with the flag on.
        #
        # The rule is therefore inverted: the escape hatch is allowed ONLY in an environment
        # explicitly recognised as local, and refused everywhere else -- including any
        # environment name nobody anticipated. Fail closed on the unknown, which is the same
        # posture core/tenancy.py and scanner_engine/scope_guard.py already take.
        if self.dev_auto_authorize_targets and not self.is_local_environment:
            raise RuntimeError(
                "Insecure configuration: DEV_AUTO_AUTHORIZE_TARGETS is enabled with "
                f"ENVIRONMENT={self.environment!r}. This flag bypasses the target-ownership "
                "authorization guardrail entirely -- MBS would scan targets with no proof of "
                "authorization. It is permitted only in a local environment "
                f"({', '.join(sorted(_LOCAL_ENVIRONMENTS))}). Unset it, or set ENVIRONMENT to "
                "a local value if this really is a developer machine."
            )

        if not self.is_production:
            return

        # MBS.SC -- THE SCANNER EXECUTION PLANE VALIDATES DIFFERENT INVARIANTS.
        #
        # Every check below this point asks "is this control-plane credential safe?" --
        # JWT signing key, S3 credentials, the database DSN, CORS/TRUSTED_HOSTS, the AI
        # budget. The scanner execution plane deliberately HAS NONE OF THEM (Property B),
        # so running those checks against it fails on the absence of things whose absence
        # is the entire point: verified directly, a production scanner refused to boot with
        # "JWT_SECRET_KEY is a placeholder / DATABASE_URL uses default dev credentials".
        #
        # This is NOT a relaxation. The execution plane is held to its OWN invariants,
        # which are stricter in the direction that matters for it: it must not possess a
        # control-plane credential at all, and it must know where its manager is. A
        # scanner that somehow acquired a real DSN fails here, where the control-plane
        # branch would have happily accepted it as "a good production credential".
        if self.scanner_execution_plane:
            exec_problems: list[str] = []
            from apps.api.celery_app.startup_security import (
                ExecutionPlaneCredentialError,
                enforce_execution_plane_credentials,
            )

            try:
                enforce_execution_plane_credentials()
            except ExecutionPlaneCredentialError as exc:
                exec_problems.append(str(exc))
            if not self.scanner_manager_url:
                exec_problems.append(
                    "SCANNER_MANAGER_URL must be set on a scanner execution worker: it is "
                    "the only control-plane endpoint the execution plane may use."
                )
            if self.dev_auto_authorize_targets:
                exec_problems.append("DEV_AUTO_AUTHORIZE_TARGETS must never be set on a scanner.")

            # DEDICATED VPN EGRESS. Validated here, at startup, because every one of these
            # gaps produces the SAME dangerous runtime symptom if left to be discovered
            # later: a worker that believes it is a VPN worker while its traffic leaves
            # over the platform's own address. Fail to start instead.
            mode = (self.scanner_egress_mode or "direct").strip().lower()
            if mode not in ("direct", "vpn"):
                exec_problems.append(
                    f"SCANNER_EGRESS_MODE must be 'direct' or 'vpn', not {mode!r}. It is "
                    f"declared explicitly and never inferred, so an unrecognised value is "
                    f"a refusal rather than a silent fallback to direct egress."
                )
            elif mode == "vpn":
                if self.scanner_site_id:
                    # The two roles are mutually exclusive by design: a site worker holds a
                    # customer tunnel and must not also be a platform internet exit.
                    exec_problems.append(
                        "SCANNER_EGRESS_MODE=vpn cannot be combined with SCANNER_SITE_ID. "
                        "A private-site worker and the VPN-egress worker are separate "
                        "roles on separate networks; one container must never be both."
                    )
                for name, value in (
                    ("SCANNER_VPN_EGRESS_PRIVATE_KEY_FILE",
                     self.scanner_vpn_egress_private_key_file),
                    ("SCANNER_VPN_EGRESS_PEER_PUBLIC_KEY",
                     self.scanner_vpn_egress_peer_public_key),
                    ("SCANNER_VPN_EGRESS_ENDPOINT_HOST",
                     self.scanner_vpn_egress_endpoint_host),
                    ("SCANNER_VPN_EGRESS_ADDRESS", self.scanner_vpn_egress_address),
                ):
                    if not value:
                        exec_problems.append(
                            f"{name} must be set when SCANNER_EGRESS_MODE=vpn; without it "
                            f"the egress tunnel cannot be established and target traffic "
                            f"would have no VPN path."
                        )
                if not self.scanner_vpn_egress_exit_ip_url:
                    exec_problems.append(
                        "SCANNER_VPN_EGRESS_EXIT_IP_URL must be set when "
                        "SCANNER_EGRESS_MODE=vpn: tunnel-up and a handshake do not prove "
                        "traffic is using the tunnel, so exit-IP verification is required."
                    )
                if not self.vpn_egress_dispatch_cidr_list:
                    exec_problems.append(
                        "SCANNER_VPN_EGRESS_DISPATCH_CIDRS must be set when "
                        "SCANNER_EGRESS_MODE=vpn: the kill-switch denies egress by default, "
                        "so the manager plane must be named explicitly or this worker "
                        "cannot reach its manager."
                    )
            if exec_problems:
                raise RuntimeError(
                    "Refusing to start the scanner execution plane with insecure "
                    "configuration:\n  - " + "\n  - ".join(exec_problems)
                )
            return

        problems: list[str] = []
        # A secret the operator declared via `<NAME>_FILE` but that could not be read. The
        # inherited value (typically a dev default from .env) must NOT be allowed to stand in
        # for it -- that is exactly the silent substitution the file-precedence rule exists to
        # prevent, so fail closed instead of booting on the wrong credential.
        for file_var in _UNREADABLE_FILE_SECRETS:
            problems.append(
                f"{file_var} is set but its file could not be read; the secret cannot be "
                "loaded and an inherited value must not be used in its place."
            )
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
        # AI-2.1: fallback providers must be known and must not include the primary.
        for name in self.ai_fallback_providers:
            if name not in ("openrouter", "anthropic", "local", "deepseek"):
                problems.append(f"AI_FALLBACK_PROVIDERS contains unknown provider '{name}'.")
            elif name == self.ai_provider:
                problems.append(f"AI_FALLBACK_PROVIDERS must not include the primary provider '{name}'.")
        if not self.ssl_verify:
            problems.append("SSL_VERIFY is disabled; never disable TLS verification in production.")
        if not self.rate_limit_enabled:
            problems.append("RATE_LIMIT_ENABLED must be true in production (unrestricted limits are unsafe).")
        # F-08: the refresh cookie carries a 7-day credential. Without Secure it would be sent
        # over plaintext http, so a network attacker could lift it -- exactly the exposure the
        # move off localStorage was meant to remove. Production serves TLS (F-01), so there is
        # no legitimate reason for this to be false there.
        if not self.refresh_cookie_secure:
            problems.append(
                "REFRESH_COOKIE_SECURE must be true in production: the refresh cookie is a "
                "long-lived credential and must never travel over plaintext http."
            )
        if self.refresh_cookie_samesite.lower() not in ("strict", "lax"):
            problems.append(
                f"REFRESH_COOKIE_SAMESITE must be 'strict' or 'lax' in production, not "
                f"'{self.refresh_cookie_samesite}': 'none' would attach the refresh cookie to "
                "cross-site requests and reintroduce CSRF on /auth/refresh."
            )
        # Rate-limit IDENTITY. Production mandates rate limiting above, but a limiter is only as
        # good as the client identity it buckets on. The app cannot observe how many proxies sit
        # in front of it, and guessing is unsafe in BOTH directions: too low and every anonymous
        # client shares one bucket; too high and the Nth-from-right read reaches into
        # caller-controlled X-Forwarded-For entries, letting anyone forge a bucket key. So
        # production must DECLARE the hop count instead of inheriting the default. 0 remains a
        # valid and safe answer -- it just has to be a deliberate one.
        if "trusted_proxy_count" not in self.model_fields_set:
            problems.append(
                "TRUSTED_PROXY_COUNT must be set explicitly in production: the number of trusted "
                "proxies in front of this app that APPEND to X-Forwarded-For (0 = nothing in "
                "front, so X-Forwarded-For is ignored and the direct peer is used). Determine it "
                "from the real ingress chain -- never guess. See docs/runbooks/deployment.md."
            )
        if self.metrics_mode == "public":
            problems.append("METRICS_MODE must not be 'public' in production.")
        # MFA Step 3: production must be able to encrypt TOTP secrets at rest.
        if not self.mfa_encryption_key:
            problems.append("MFA_ENCRYPTION_KEY must be set in production (MFA cannot function without it).")
        # --- F-06: a METERED AI provider in production must have a spend cap -----------------
        # The production overlay ships AI_PROVIDER=openrouter with a real API key on api,
        # worker AND worker-default, while budget enforcement defaulted OFF -- so the shipped
        # production configuration billed without limit. It is reachable by any authenticated
        # member holding project:read (POST /assistant/ask), bounded only by RATE_LIMIT_AI
        # ("30/minute"), which caps REQUEST RATE, not COST -- and which itself fails open when
        # Redis is down. A runaway agent loop or a single abusive tenant therefore had no
        # spend ceiling at all.
        #
        # TWO independent switches had to be right (`ai_budget_enforce` AND a positive
        # `ai_daily_budget_usd`); setting only one silently left spend unlimited, which is the
        # trap this check exists to catch -- both partial configurations are refused by name.
        #
        # Scope is deliberately narrow: only when AI is actually LIVE (a real key is present)
        # and the provider is metered. `local` (self-hosted Ollama) has no per-token cost, so
        # it is exempt -- this guards a billing/abuse boundary, not AI usage as such.
        if self.ai_enabled and self.ai_provider in _METERED_AI_PROVIDERS:
            if not self.ai_budget_enforce:
                problems.append(
                    f"AI_BUDGET_ENFORCE must be true in production with the metered AI provider "
                    f"'{self.ai_provider}': without it a runaway agent loop or an abusive tenant "
                    "can bill without limit (RATE_LIMIT_AI caps request rate, not cost)."
                )
            if self.ai_daily_budget_usd <= 0:
                problems.append(
                    f"AI_DAILY_BUDGET_USD must be greater than 0 in production with the metered "
                    f"AI provider '{self.ai_provider}': enforcement is inert without a positive "
                    "cap, so spend stays unlimited even with AI_BUDGET_ENFORCE=true."
                )
        if self.dev_auto_authorize_targets:
            problems.append(
                "DEV_AUTO_AUTHORIZE_TARGETS must never be enabled in production -- it bypasses the "
                "target-ownership authorization guardrail entirely."
            )
        # DR-2: if backup encryption is enabled, the key must be present (fail closed).
        if self.backup_enabled and self.backup_encryption_enabled and not self.backup_encryption_key:
            problems.append("BACKUP_ENCRYPTION_KEY must be set when BACKUP_ENCRYPTION_ENABLED is true.")
        # E1: if email alerts are enabled, SMTP host + from-address are mandatory (fail closed).
        if self.email_enabled and self.email_provider == "smtp" and (
            not self.smtp_host or not self.email_from_address
        ):
            problems.append("SMTP_HOST and EMAIL_FROM_ADDRESS must be set when EMAIL_ENABLED is true.")
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
    # Secret loading order, HIGHEST PRECEDENCE LAST: explicit env / Docker-K8s env ->
    # external backend (setdefault, no-op unless SECRETS_BACKEND is set; see core/secrets.py)
    # -> <NAME>_FILE (Docker/K8s secret files), which OVERRIDES the earlier two. A declared
    # secret file is an explicit delivery mechanism and must not be defeated by an inherited
    # default -- see _resolve_file_secrets() for why that ordering is load-bearing.
    from apps.api.core.secrets import load_external_secrets

    load_external_secrets()
    _resolve_database_url_from_parts()
    _resolve_file_secrets()
    # AUDIT-013: pydantic BaseSettings populates every field from the environment/defaults
    # at construction; mypy (without the pydantic plugin) reads the generated __init__ as
    # requiring each field explicitly. Verified correct at runtime by the whole test suite.
    return Settings()  # type: ignore[call-arg]
