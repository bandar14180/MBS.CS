"""Notification channel provider interface (P2-12).

A seam for delivering notifications over multiple channels. In-app persistence is
the default and remains the wired behavior; email / Slack / Teams / webhook are
future channels behind this same interface. Additive: the existing
notifications.service functions are unchanged. A concrete channel is selected/
extended via the registry below; unimplemented channels raise a clear error rather
than silently dropping a message.
"""
from abc import ABC, abstractmethod
from typing import Any


class NotificationProvider(ABC):
    """Deliver a single notification over one channel."""

    name: str = "base"

    @abstractmethod
    async def send(
        self,
        *,
        title: str,
        body: str | None = None,
        workspace_id: Any = None,
        type: str = "info",
        severity: str = "info",
    ) -> None:
        ...


class InAppNotificationProvider(NotificationProvider):
    """The default channel: an in-app notification row. Wraps the existing
    persistence path (notifications.service.create_notification) so current callers
    keep working unchanged; this provider exists so other channels can be added
    uniformly behind the same interface."""

    name = "in_app"

    def __init__(self, db=None):
        self._db = db

    async def send(self, *, title, body=None, workspace_id=None, type="info", severity="info") -> None:
        if self._db is None or workspace_id is None:
            raise ValueError("InAppNotificationProvider requires db and workspace_id")
        from apps.api.modules.notifications.service import create_notification

        await create_notification(
            self._db, workspace_id=workspace_id, type=type, title=title, severity=severity, body=body
        )


class EmailNotificationProvider(NotificationProvider):
    """E1: deliver an alert over email (SMTP). Async-compatible -- the blocking smtplib call runs
    in a worker thread so this satisfies the async interface without blocking the event loop.
    Constructed with its recipients + settings (the fixed NotificationProvider.send signature
    carries content only). Safe when disabled: with email_enabled=False, send() is a no-op, so
    the channel can always be selected without risk."""

    name = "email"

    def __init__(self, settings=None, recipients: list[str] | None = None):
        from apps.api.core.config import get_settings

        self._settings = settings or get_settings()
        self._recipients = list(recipients or [])

    async def send(self, *, title, body=None, workspace_id=None, type="info", severity="info") -> None:
        import asyncio

        s = self._settings
        if not s.email_enabled:
            return  # default-off: nothing is ever sent
        recipients = self._recipients or list(s.email_admin_recipients)
        if not recipients:
            return
        from apps.api.modules.notifications.email import smtp_send

        # Run the blocking SMTP call off the event loop (async-compatible).
        await asyncio.to_thread(smtp_send, s, recipients, title, body or "")


class _UnimplementedProvider(NotificationProvider):
    """Placeholder for a planned channel; raises so nothing is silently dropped."""

    def __init__(self, name: str):
        self.name = name

    async def send(self, *, title, body=None, workspace_id=None, type="info", severity="info") -> None:
        raise NotImplementedError(f"Notification channel '{self.name}' is not implemented yet.")


# Live channels: in_app + email. Slack/Teams/Webhook remain declared placeholders.
_CHANNELS = {"slack", "teams", "webhook"}


def get_notification_provider(channel: str = "in_app", *, db=None) -> NotificationProvider:
    if channel == "in_app":
        return InAppNotificationProvider(db=db)
    if channel == "email":
        return EmailNotificationProvider()
    if channel in _CHANNELS:
        return _UnimplementedProvider(channel)
    raise ValueError(f"Unknown notification channel '{channel}'")
