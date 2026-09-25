"""How long has THIS process been able to observe the world? -- MBS.SC Phase 8 (P8-F).

WHY THIS EXISTS. `reap_stale_workers` suspends a worker whose last heartbeat is older than
`worker_stale_after_seconds`. That predicate is correct, but it measures ONE thing and is
read as another:

    what it measures : time since the last successful worker -> manager round-trip
    how it is read   : time since the worker was last alive

Those two quantities are equal only while the platform is up. They diverge by exactly the
platform's own downtime, because `scanner_workers.last_seen_at` is written only by
`record_heartbeat`, reachable only through `POST /v1/heartbeat` -- so while the manager and
database are down, a perfectly healthy worker CANNOT refresh it. Verified live: an 11-minute
host restart produced 703s of apparent silence, 677s of which (96.3%) was the platform being
off, and the sweep suspended the entire fleet on the first tick after recovery.

Celery Beat makes that first tick immediate. Its scheduler state is persisted
(`celerybeat-schedule`), and `ScheduleEntry.update()` copies only task/schedule/args/kwargs/
options -- `last_run_at` is deliberately PRESERVED. So after any restart the stored
`last_run_at` predates the outage, `remaining_estimate()` is negative, and the task is due
at once: measured at +163ms after `beat: Starting...`, reproducibly, across five restarts.

So the reaper cannot wait for Beat to pace it, and it cannot learn the difference from the
worker row. It needs one fact the row does not carry: how long the platform executing the
sweep has actually been in a position to hear a heartbeat. That is all this module provides.

MONOTONIC, NOT WALL CLOCK. `time.monotonic()` cannot be dragged backwards or forwards by an
NTP correction or a DST change, and a host restart is precisely when a clock jump is most
likely -- a wall-clock uptime could otherwise read as negative or hours-long and either
disable the reaper or fail to gate it. The worker timestamps themselves stay exactly as they
are: `last_seen_at` remains UTC wall clock, compared against a UTC cutoff, because it is
shared across processes and must be. Monotonic is used ONLY for this process-local "how long
have I been up" question, which is the one place it is both correct and safer.

PROCESS SCOPE, AND WHY IT SURVIVES CHILD RECYCLING. `workers.reap_stale` carries no explicit
route, so it runs on `task_default_queue="default"` -- executed by the `worker-default`
Celery worker, NOT by Beat (which only dispatches) and NOT by the API. That worker runs
`concurrency: 12 (prefork)` with `worker_max_tasks_per_child = 50`, so the child that
executes any given sweep is regularly replaced.

That recycling is the trap this module is written around. A timestamp captured when a CHILD
starts would reset every 50 tasks, re-arming the grace window forever and silently disabling
the reaper for good -- a far worse outcome than the incident, because it would be invisible.

THAT IS NOT HYPOTHETICAL: IT SHIPPED ONCE AND WAS CAUGHT IN RUNTIME VALIDATION. The first
version of this work imported this module LAZILY, inside `reap_stale_workers()`. The anchor
was then first touched inside a forked CHILD, on that child's first sweep, so every child
started its own origin and every sweep logged `uptime=0.0s grace=600.0s` -- observed live on
2026-09-17 from `ForkPoolWorker-1` and `ForkPoolWorker-8`, 300s apart. The grace could never
expire and stale detection was disabled outright.

WHAT MAKES IT CORRECT NOW: this module is imported at MODULE SCOPE by
`apps/api/celery_app/tasks/scan_tasks.py`, which is in the Celery app's `include=` list and
is therefore loaded by `loader.import_default_modules()` during MainProcess boot -- before
prefork forks anything (verified empirically, not assumed). `apps/api/modules/scanner_workers/
service.py` also imports it at module scope. Children inherit the parent's already-initialised
module rather than re-executing it, and a RECYCLED child is forked from that same parent, so
it inherits the original anchor too. `time.monotonic()` is measured from an arbitrary fixed
point, not from process start, so the value stays comparable across the fork boundary.

Under a `spawn` start method a child would re-import and reset this anchor. That is not the
deployed configuration (Linux/fork, asserted by a test), and the failure direction is the
conservative one -- a freshly spawned child would gate MORE, never less, and would still
converge once it had been up for the window.
"""
from __future__ import annotations

import time

# Captured at import: once per process, before any task runs. Inherited by forked children.
_PROCESS_START_MONOTONIC: float = time.monotonic()


def process_uptime_seconds() -> float:
    """Seconds since this process (or the parent it was forked from) started.

    Never negative and never affected by a clock adjustment, which is the whole point --
    see the module docstring.
    """
    return max(0.0, time.monotonic() - _PROCESS_START_MONOTONIC)


def within_startup_grace(grace_seconds: float) -> bool:
    """Is the platform still too freshly started to judge a worker silent?

    True while `uptime < grace_seconds`. The boundary is deliberately EXCLUSIVE on the
    grace side (`<`, not `<=`), mirroring the reaper's own strict `<` cutoff comparison so
    the two boundaries agree: at exactly the threshold, normal evaluation resumes.

    A non-positive grace disables the gate entirely, which is what lets the existing tests
    -- and any caller that has its own reason to sweep unconditionally -- keep the original
    behaviour by passing 0.
    """
    if grace_seconds <= 0:
        return False
    return process_uptime_seconds() < grace_seconds
