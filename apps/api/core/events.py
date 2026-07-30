"""A tiny in-process domain event bus (P2-10).

Purpose: give the findings pipeline a decoupling seam so new reactions
(dashboards, extra notifications, exports) can subscribe to domain events without
editing the orchestrator. It deliberately does NOT change existing behavior --
the scan-completed notification is simply registered as the first subscriber and
does exactly what the previous direct call did.

Synchronous, in-process, best-effort: a subscriber that raises is logged and
skipped so one bad subscriber never breaks the emitter or the scan. Handlers may
be sync or async. Events may carry live objects (db session, ORM row) for
same-transaction subscribers -- this is an in-process bus, not a serialized queue.
"""
import inspect
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("mbs.events")


@dataclass
class ScanCompleted:
    """Emitted when a scan reaches a terminal state (completed /
    completed_with_errors / failed). `db` and `scan` are provided for in-process,
    same-transaction subscribers and are not part of any serialized contract."""

    scan_id: Any
    workspace_id: Any
    status: str
    db: Any = field(default=None, repr=False)
    scan: Any = field(default=None, repr=False)


_subscribers: dict[type, list[Callable[[Any], Any]]] = defaultdict(list)


def subscribe(event_type: type, handler: Callable[[Any], Awaitable[None] | None]) -> None:
    """Register a handler for an event type. Idempotent per handler object."""
    if handler not in _subscribers[event_type]:
        _subscribers[event_type].append(handler)


def clear_subscribers(event_type: type | None = None) -> None:
    """Test helper: drop subscribers (all, or for one event type)."""
    if event_type is None:
        _subscribers.clear()
    else:
        _subscribers.pop(event_type, None)


async def emit(event: Any) -> None:
    """Dispatch `event` to every subscriber for its type. Best-effort: a failing
    subscriber is logged and skipped, never propagated."""
    for handler in list(_subscribers[type(event)]):
        try:
            result = handler(event)
            if inspect.isawaitable(result):
                await result
        except Exception:  # noqa: BLE001 -- a subscriber must not break the emitter
            logger.warning("event_subscriber_failed event=%s handler=%s", type(event).__name__, handler, exc_info=True)
