"""Tool-binary preflight -- "is this scanner actually installed here?"

Every registered runner shells out to an external binary. When that binary is
missing from the executing process's PATH, `asyncio.create_subprocess_exec`
raises FileNotFoundError, the orchestrator correctly records
`ToolRun.status="failed"` with the error -- and the platform's only visible
symptom is a report with fewer findings. From the report alone, "the tool ran
and found nothing" and "the tool was never installed" look identical.

This module makes the difference explicit and cheap to check:

  * `preflight()` resolves every TOOL_REGISTRY entry's `binary` via PATH.
  * `log_preflight()` emits one structured line at worker startup, so the very
    first thing in the worker log answers the question.
  * the `/api/v1/scan-capabilities/pipeline` endpoint surfaces the same data to
    the UI, so the scan form can flag a tool as unavailable BEFORE a scan runs.

The single source of truth is `BaseToolRunner.binary` on each runner -- there is
deliberately no second name->binary map here to drift out of sync with the
registry (that drift is exactly the class of bug this module exists to expose).
"""
import json
import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass

from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY

logger = logging.getLogger("mbs.scanner.preflight")

# Where the worker publishes its own preflight for the API to read back.
#
# This indirection is NOT incidental: the scanner binaries are installed ONLY by
# infra/docker/Dockerfile.worker. The API image has none of them, so a `shutil.which`
# performed in the API process would report every tool as missing -- worse than saying
# nothing, because the scan form would grey out tools that are in fact installed and
# working. The authoritative answer can only come from the process that actually runs
# them, so the worker writes it here at startup and the API reads it.
PREFLIGHT_REDIS_KEY = "mbs:scanner:preflight"
# Comfortably longer than any redeploy gap, short enough that a decommissioned worker's
# claim doesn't linger indefinitely.
PREFLIGHT_TTL_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class BinaryStatus:
    tool: str
    binary: str
    available: bool
    path: str | None
    # Extra runtime prerequisites beyond the binary itself (nuclei's template
    # directory, ffuf's wordlist). Empty when the tool has none or all are met;
    # a non-empty list means the binary exists but the tool will still no-op.
    missing_requirements: list[str]


def _missing_requirements(tool: str) -> list[str]:
    """Non-binary prerequisites a tool needs to actually produce results.

    Both of these are set only by infra/docker/Dockerfile.worker, so outside that
    image they are the second-most-common reason a present binary still yields
    nothing (nuclei loads 0 templates; ffuf refuses to run)."""
    from apps.api.core.config import get_settings

    settings = get_settings()
    missing: list[str] = []
    if tool in ("nuclei", "nuclei-dast"):
        templates = (settings.nuclei_templates_dir or "").strip()
        if not templates:
            missing.append("NUCLEI_TEMPLATES_DIR is unset (nuclei falls back to an ambient search)")
        elif not os.path.isdir(templates):
            missing.append(f"NUCLEI_TEMPLATES_DIR={templates!r} does not exist")
    if tool == "ffuf":
        wordlist = (settings.ffuf_wordlist_path or "").strip()
        if not wordlist:
            missing.append("FFUF_WORDLIST_PATH is unset (the runner hard-fails without it)")
        elif not os.path.isfile(wordlist):
            missing.append(f"FFUF_WORDLIST_PATH={wordlist!r} does not exist")
    return missing


def preflight() -> list[BinaryStatus]:
    """Every registered tool's binary availability, in pipeline (phase) order."""
    out: list[BinaryStatus] = []
    for name, cls in sorted(TOOL_REGISTRY.items(), key=lambda kv: (kv[1].phase, kv[0])):
        binary = cls.binary or name
        path = shutil.which(binary)
        out.append(
            BinaryStatus(
                tool=name,
                binary=binary,
                available=path is not None,
                path=path,
                missing_requirements=_missing_requirements(name) if path else [],
            )
        )
    return out


def missing_tools() -> list[str]:
    return [s.tool for s in preflight() if not s.available]


def _redis():
    """Best-effort Redis client; None if redis/config is unavailable (same fail-soft
    pattern as core.observability's reliability signals)."""
    try:
        import redis

        from apps.api.core.config import get_settings

        return redis.from_url(get_settings().redis_url)
    except Exception:  # noqa: BLE001
        return None


def publish_preflight() -> None:
    """Publish THIS process's preflight so other processes (the API) can report it.
    Best-effort: a Redis outage just means the API answers 'unknown'."""
    client = _redis()
    if client is None:
        return
    try:
        payload = {
            "published_at": time.time(),
            "tools": {s.tool: asdict(s) for s in preflight()},
        }
        client.set(PREFLIGHT_REDIS_KEY, json.dumps(payload), ex=PREFLIGHT_TTL_SECONDS)
    except Exception:  # noqa: BLE001
        logger.debug("scanner.preflight_publish_failed", exc_info=True)


def published_preflight() -> dict[str, dict] | None:
    """The worker's published preflight, or None when nothing has been published (no
    worker has started yet, or Redis is unreachable). None means UNKNOWN -- callers must
    not render it as 'missing'."""
    client = _redis()
    if client is None:
        return None
    try:
        raw = client.get(PREFLIGHT_REDIS_KEY)
        if not raw:
            return None
        tools = json.loads(raw).get("tools")
        return tools if isinstance(tools, dict) else None
    except Exception:  # noqa: BLE001
        return None


def effective_preflight() -> dict[str, dict] | None:
    """What to report to clients.

    Prefer the worker's published view -- it is the only process whose PATH matters,
    because it is the one that executes the tools. Fall back to a local resolution only
    when this process can itself see the binaries (i.e. it IS a worker, or a dev box with
    the tools installed); if neither holds, return None for 'unknown' rather than
    asserting that every tool is missing."""
    published = published_preflight()
    if published:
        return published
    local = {s.tool: asdict(s) for s in preflight()}
    if any(s["available"] for s in local.values()):
        return local
    return None


def log_preflight() -> None:
    """One structured startup line per worker process. Never raises: a preflight
    that failed to run must not stop the worker from serving."""
    try:
        statuses = preflight()
    except Exception:  # noqa: BLE001 -- diagnostics must never break startup
        logger.warning("scanner.preflight_failed", exc_info=True)
        return

    available = [s.tool for s in statuses if s.available]
    missing = [s.tool for s in statuses if not s.available]
    degraded = {s.tool: s.missing_requirements for s in statuses if s.available and s.missing_requirements}

    logger.info(
        "scanner.preflight tools_available=%d/%d available=%s missing=%s",
        len(available), len(statuses), ",".join(available) or "-", ",".join(missing) or "-",
    )
    if missing:
        logger.error(
            "scanner.preflight_missing_binaries missing=%s -- scans requesting these tools will record "
            "ToolRun.status='failed' (FileNotFoundError) and contribute NO findings. The binaries are "
            "installed by infra/docker/Dockerfile.worker; a non-container worker must install them itself.",
            ",".join(missing),
        )
    for tool, reqs in degraded.items():
        logger.warning("scanner.preflight_degraded tool=%s reasons=%s", tool, "; ".join(reqs))

    publish_preflight()
