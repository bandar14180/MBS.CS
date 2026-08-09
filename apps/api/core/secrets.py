"""Pluggable secret loading (P1-9).

Loading order (first present wins for each secret):
  1. Explicit process environment `<NAME>` -- includes Docker/Kubernetes secrets
     injected as env vars, and anything set in the shell / compose `.env`.
  2. `<NAME>_FILE` -> file contents. Covers **Docker Secrets** (mounted at
     /run/secrets/*), **Kubernetes Secrets** (mounted files), and Vault-Agent
     templated files. Resolved by config._resolve_file_secrets().
  3. An external secrets backend selected by `SECRETS_BACKEND` (e.g. AWS Secrets
     Manager) -- see below. Only consulted when explicitly configured, and it uses
     setdefault so it never overrides 1 or 2.

Nothing here hardcodes, logs, or writes secrets to disk. The external backend is
an interface: its optional dependency (boto3) is imported lazily so it is not
required unless the backend is actually selected.
"""
import json
import os
from typing import Protocol


class SecretProvider(Protocol):
    """A source of `{ENV_NAME: value}` secrets."""

    def load(self) -> dict[str, str]: ...


class AwsSecretsManagerProvider:
    """Fetch a JSON secret bundle from AWS Secrets Manager and return it as a
    flat `{ENV_NAME: value}` map. Interface/stub for production: boto3 is imported
    lazily, so it is NOT a runtime dependency unless SECRETS_BACKEND=aws is set."""

    def __init__(self, secret_id: str, region: str | None = None):
        self._secret_id = secret_id
        self._region = region

    def load(self) -> dict[str, str]:
        import boto3  # lazy: optional, only when this backend is used

        client = boto3.client("secretsmanager", region_name=self._region)
        resp = client.get_secret_value(SecretId=self._secret_id)
        data = json.loads(resp.get("SecretString") or "{}")
        return {str(k): str(v) for k, v in data.items()}


def load_external_secrets() -> None:
    """Populate os.environ from the configured external backend BEFORE Settings is
    built. No-op unless `SECRETS_BACKEND` is set. Uses setdefault, so explicit env
    and `<NAME>_FILE` values always win. Interface-only in this release: an
    unavailable/misconfigured backend must never crash startup -- config
    validation still surfaces any missing secret."""
    backend = os.environ.get("SECRETS_BACKEND", "").strip().lower()
    if backend != "aws":
        return
    secret_id = os.environ.get("AWS_SECRETS_ID", "").strip()
    if not secret_id:
        return
    try:
        provider = AwsSecretsManagerProvider(secret_id, os.environ.get("AWS_REGION") or None)
        for key, value in provider.load().items():
            os.environ.setdefault(key, value)
    except Exception:  # noqa: BLE001 -- optional backend must not break boot
        pass
