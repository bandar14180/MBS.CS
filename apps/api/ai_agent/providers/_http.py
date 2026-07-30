import httpx

from apps.api.core.config import get_settings


def sync_client(timeout_s: float) -> httpx.Client:
    """A sync httpx.Client that honors enterprise TLS settings: a custom CA bundle
    (corporate root) or an explicit verification toggle. Proxies are read from the
    environment by httpx (trust_env=True); core.config.configure_networking()
    populates HTTP(S)_PROXY there. Centralized so every provider gets the same
    behavior and TLS-inspecting proxies can be supported without disabling
    verification by default."""
    return httpx.Client(timeout=timeout_s, verify=get_settings().httpx_verify)
