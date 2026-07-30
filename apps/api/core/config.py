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

    ai_max_tokens: int = 4096
    ai_request_timeout_s: float = 60.0
    ai_max_retries: int = 3

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
        """The API key for the currently selected provider ("" if unset)."""
        return {
            "openrouter": self.openrouter_api_key,
            "anthropic": self.anthropic_api_key,
        }.get(self.ai_provider, "")

    @property
    def active_ai_model(self) -> str:
        """The model id the selected provider will send."""
        return self.openrouter_model if self.ai_provider == "openrouter" else self.ai_model

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
        if self.ai_provider not in ("openrouter", "anthropic"):
            problems.append(f"AI_PROVIDER '{self.ai_provider}' is not a known provider.")
        if problems:
            raise RuntimeError(
                "Refusing to start in production with insecure configuration:\n  - "
                + "\n  - ".join(problems)
            )


@lru_cache
def get_settings() -> Settings:
    _resolve_file_secrets()
    return Settings()
