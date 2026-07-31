"""Unit tests for P2 seams: event bus, storage provider, notification provider.
Pure -- no DB/broker/network."""
import asyncio
from dataclasses import dataclass

import pytest


# --- event bus (P2-10) ---

@dataclass
class _Ping:
    status: str


def test_event_bus_dispatches_and_isolates_subscriber_failures() -> None:
    from apps.api.core import events

    got: list[str] = []

    def bad(_e):
        raise RuntimeError("boom")

    def good(e):
        got.append(e.status)

    events.subscribe(_Ping, bad)
    events.subscribe(_Ping, good)
    try:
        asyncio.run(events.emit(_Ping(status="ok")))
        assert got == ["ok"]  # good still ran despite bad raising
    finally:
        events.clear_subscribers(_Ping)


def test_event_bus_supports_async_handlers() -> None:
    from apps.api.core import events

    seen: list[str] = []

    async def handler(e):
        seen.append(e.status)

    events.subscribe(_Ping, handler)
    try:
        asyncio.run(events.emit(_Ping(status="async")))
        assert seen == ["async"]
    finally:
        events.clear_subscribers(_Ping)


# --- storage provider (P2-11) ---

def test_storage_provider_default_is_s3() -> None:
    from apps.api.scanner_engine.storage_provider import S3StorageProvider, get_storage_provider

    assert isinstance(get_storage_provider(), S3StorageProvider)


def test_storage_provider_unknown_backend_raises(monkeypatch) -> None:
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine import storage_provider

    monkeypatch.setattr(get_settings(), "storage_provider", "azure_blob")
    with pytest.raises(NotImplementedError):
        storage_provider.get_storage_provider()


# --- notification provider (P2-12) ---

def test_notification_provider_factory() -> None:
    from apps.api.modules.notifications.providers import (
        InAppNotificationProvider,
        _UnimplementedProvider,
        get_notification_provider,
    )

    assert isinstance(get_notification_provider("in_app"), InAppNotificationProvider)
    assert isinstance(get_notification_provider("slack"), _UnimplementedProvider)
    with pytest.raises(ValueError):
        get_notification_provider("carrier-pigeon")


def test_unimplemented_channel_send_raises() -> None:
    from apps.api.modules.notifications.providers import get_notification_provider

    provider = get_notification_provider("email")
    with pytest.raises(NotImplementedError):
        asyncio.run(provider.send(title="t", workspace_id="w"))


# --- scanner capability registry (P0-2) ---

def test_capability_registry_supported_and_scanners() -> None:
    from apps.api.scanner_engine import capabilities

    assert capabilities.is_supported("domain") is True
    assert capabilities.is_supported("ip_range") is True
    assert capabilities.is_supported("repo") is False
    assert capabilities.is_supported("cloud_account") is False
    assert "subfinder" in capabilities.scanners_for("domain")
    assert "subfinder" not in capabilities.scanners_for("ip_range")  # domain-only tool
    assert capabilities.scanners_for("repo") == []


def test_config_can_narrow_but_not_widen_capabilities(monkeypatch) -> None:
    from apps.api.core.config import get_settings
    from apps.api.scanner_engine import capabilities

    monkeypatch.setattr(get_settings(), "supported_target_types", ["domain", "repo"])
    assert capabilities.is_supported("repo") is False       # no engine -> config can't enable
    assert capabilities.is_supported("domain") is True
    assert capabilities.is_supported("ip_range") is False   # config narrowed it out
