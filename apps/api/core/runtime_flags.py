"""Runtime-mutable operational flags -- MBS.SC PHASE 8 (P8-D).

WHY THIS EXISTS
---------------
`private_scanning_emergency_disable` is the platform-wide kill switch for private scanning.
It was correct in every respect except how its value reached a RUNNING process: it is read
through `get_settings()`, which is `@lru_cache`d, so the first call freezes the value for the
life of the process. Measured inside the live scanner-manager:

    initial:                      False
    after env flip (no restart):  False
    same cached object?           True

Flipping the environment variable therefore did nothing, and the documented procedure was
"set the variable, THEN RESTART scanner-manager". A container's environment is immutable
after start, so no env-based approach can fix that -- an emergency control whose activation
requires a restart is slow exactly when speed matters.

THE MECHANISM
-------------
A read-only bind-mounted DIRECTORY (`./runtime` -> `/run/mbs:ro`) in which the operator
creates or removes a sentinel FILE. Existence is the signal; the file's content is never
read, so there is no blank/`TRUE`/`1`/half-written case to misparse -- every one of those
would have been an opportunity to fail OPEN.

A DIRECTORY is mounted rather than the file itself, deliberately: a single-file bind mount is
pinned to an inode on Linux, so an atomic replace (`mv`, which is what a careful operator
script does) leaves the container reading the OLD file forever. Mounting the directory means
create/delete/replace are all observed correctly. Verified empirically against Docker before
this was written.

THE SAFETY RULES (requirements, not preferences)
------------------------------------------------
  * The sentinel can only ever ADD restriction. The effective value is the logical OR of the
    environment setting and the sentinel, so a missing file can NEVER re-enable scanning that
    the environment disabled. There is no path here that turns the switch off.
  * A read failure retains the LAST KNOWN value. A control plane that cannot read its own
    kill switch must not conclude "all clear".
  * With no successful read ever (failure on the very first attempt), the answer is
    DISABLED. Failing closed on an unreadable switch is the only safe default.
  * No HTTP endpoint. The switch is filesystem-only and therefore reachable only by an
    operator with host access to the deployment directory -- the same person who could
    already restart the container. It gains no new controller, and no scanner worker can
    touch it: no worker, public or private, has any host bind mount at all.

TTL
---
5 seconds. The worker lease poll is 5s (`BackoffPolicy.idle_seconds`), so the switch takes
effect within roughly one poll cycle -- "immediate" in operator terms -- while the cost stays
bounded at one `os.path.exists()` per 5s per process rather than one per request.
"""
from __future__ import annotations

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

#: Directory the runtime flag directory is mounted at inside the container. Read-only; the
#: manager can never write here (`:ro` plus `read_only: true` on the production service).
RUNTIME_FLAG_DIR = "/run/mbs"

#: Existence of this file disables private scanning platform-wide.
EMERGENCY_DISABLE_SENTINEL = "EMERGENCY_DISABLE_PRIVATE_SCANNING"

#: How long a reading is trusted before the filesystem is consulted again.
FLAG_TTL_SECONDS = 5.0


class _CachedFlag:
    """One flag's cached reading. Thread-safe: the manager serves requests concurrently, and
    two workers polling at once must not race the refresh into an inconsistent state."""

    __slots__ = ("_lock", "_value", "_read_at", "_ever_read")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: bool = False
        self._read_at: float = 0.0
        # Distinguishes "cached False" from "never successfully read", which is what makes
        # the fail-closed default correct rather than accidental.
        self._ever_read: bool = False

    def get(self, path: str, *, ttl: float, now: float) -> bool:
        with self._lock:
            if self._ever_read and (now - self._read_at) < ttl:
                return self._value
            try:
                present = os.path.exists(path)
            except Exception:  # noqa: BLE001 -- an unreadable switch must not raise upward
                if self._ever_read:
                    # RETAIN the last known value. Reverting to False here would silently
                    # re-enable scanning the operator had just disabled.
                    logger.warning(
                        "runtime_flag.read_failed path=%s -- retaining last known value=%s",
                        path, self._value,
                        extra={"event": "runtime_flag.read_failed", "retained": self._value},
                    )
                    return self._value
                # Never read successfully: fail CLOSED.
                logger.error(
                    "runtime_flag.read_failed path=%s -- no prior reading; failing closed",
                    path, extra={"event": "runtime_flag.read_failed_closed"},
                )
                return True
            if present != self._value or not self._ever_read:
                logger.info(
                    "runtime_flag.changed path=%s present=%s", path, present,
                    extra={"event": "runtime_flag.changed", "present": present},
                )
            self._value = present
            self._read_at = now
            self._ever_read = True
            return present


_emergency_flag = _CachedFlag()


def _sentinel_path() -> str:
    """Where the sentinel lives. Overridable by env for tests and for a deployment that
    mounts the directory elsewhere; it is a PATH, never the flag's value."""
    directory = os.environ.get("MBS_RUNTIME_FLAG_DIR", RUNTIME_FLAG_DIR)
    return os.path.join(directory, EMERGENCY_DISABLE_SENTINEL)


def emergency_sentinel_present(*, ttl: float = FLAG_TTL_SECONDS) -> bool:
    """True when the operator's sentinel file exists (TTL-cached, fail-closed)."""
    return _emergency_flag.get(_sentinel_path(), ttl=ttl, now=time.monotonic())


def private_scanning_emergency_disabled(settings=None, *, ttl: float = FLAG_TTL_SECONDS) -> bool:
    """The EFFECTIVE kill-switch value: environment OR sentinel.

    A logical OR, never an override -- which is what guarantees the sentinel can only add
    restriction. If the environment says private scanning is disabled, removing the file
    cannot re-enable it; the operator must change the environment (and restart) to undo a
    permanently-configured disable, exactly as before.

    Reading the environment half through the passed/settings object keeps the existing
    behaviour byte-for-byte: this function ADDS a second source, it does not replace one.
    """
    if settings is None:
        from apps.api.core.config import get_settings

        settings = get_settings()
    env_disabled = bool(getattr(settings, "private_scanning_emergency_disable", False))
    if env_disabled:
        # Short-circuit: the answer cannot change, so do not touch the filesystem at all.
        return True
    return emergency_sentinel_present(ttl=ttl)


def reset_flag_cache() -> None:
    """Drop the cached reading. FOR TESTS ONLY -- production relies on the TTL, and a
    caller that could force a re-read on demand would be a second control surface."""
    global _emergency_flag
    _emergency_flag = _CachedFlag()
