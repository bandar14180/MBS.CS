"""Where scan results and evidence go -- MBS.SC Phase 6.

BEFORE: the execution worker imported `evidence_store` and wrote to MinIO with the ROOT
credentials, and wrote findings straight into MySQL. Persistence was a library call inside
the same process that runs untrusted scanner binaries, which is what made the object store
and the database part of the scanner's blast radius. Nothing validated that the evidence a
worker wrote belonged to the tenant whose scan it was running -- there was no boundary at
which such a check could even be placed.

AFTER: the scanner speaks to a ResultSink. The execution plane gets `ManagerResultSink`,
which submits over the narrow manager API and holds no storage or database credentials at
all. The control plane (and the test suite) uses `LocalResultSink`, which keeps today's
direct-write behaviour verbatim.

This is an interface seam, NOT a security control by itself: swapping the sink is what
makes credential removal possible, and the actual authorization happens server-side in the
manager. Both facts matter -- a sink alone would be security theatre if the manager did
not re-derive tenancy on every submission, which it does.
"""
from __future__ import annotations

import abc
import asyncio
import hashlib
import logging
import random
import uuid

logger = logging.getLogger(__name__)

# Bounded retry for submissions to the manager. A result the worker already produced is
# expensive -- it represents a tool that actually ran against a live target -- so a
# TRANSIENT manager problem (a restart, a brief 5xx, a dropped connection) should not
# discard it. Bounded, because the alternative failure mode is worse: an unbounded retry
# turns one struggling manager into a worker-driven retry storm that keeps it down.
#
# 3 attempts with 0.5s/1.0s backoff costs at most ~1.5s of added latency on a genuinely
# dead manager, which is negligible against tool runtimes measured in minutes.
_POST_MAX_ATTEMPTS = 3
_POST_BACKOFF_BASE_SECONDS = 0.5
# Jitter spreads the retries of many workers that all saw the same manager blip, so they do
# not re-converge on it in lockstep.
_POST_BACKOFF_JITTER = 0.25


class ResultSubmissionFailed(RuntimeError):
    """A submission to the manager did not persist, after exhausting any retries.

    Distinct from EvidenceRejected (which means the payload is invalid and must never be
    retried). This means the RESULT IS LOST but the TOOL ITSELF RAN -- the caller is
    expected to record that distinction and carry on with the pipeline rather than treat it
    as a scan-execution failure. See executor.py for why those two are not the same thing.
    """


def _is_retryable(exc: Exception) -> bool:
    """True for failures that a later identical attempt could plausibly survive.

    5xx and transport errors are transient by definition -- the request never reached a
    decision, or the server failed to make one. A 4xx is a verdict ABOUT THIS REQUEST:
    retrying an unauthorized worker, a superseded execution token or a malformed body
    re-sends the same bytes and earns the same refusal, so it is wasted work that only
    delays the caller's own error handling. 429 is the documented exception -- it is an
    explicit "later", not a verdict -- but the manager does not currently issue one, so it
    is handled here for correctness rather than because it is expected.
    """
    import httpx

    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code >= 500 or code == 429
    # Timeouts, connection resets, DNS blips, pool timeouts: all transport-level.
    return isinstance(exc, httpx.TransportError)

# Evidence integrity limits. Enforced on BOTH sides: locally so a runaway tool cannot fill
# the store, and again server-side in the manager because a compromised worker would
# simply not run the local check.
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024  # 64 MiB
ALLOWED_EVIDENCE_TYPES = frozenset({
    "text/plain", "application/json", "application/xml", "text/xml",
    "text/html", "image/png", "image/jpeg", "application/octet-stream",
})


class EvidenceRejected(ValueError):
    """Evidence failed validation (size, type, digest, or tenancy)."""


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def validate_evidence(content: bytes, content_type: str) -> str:
    """Shared integrity checks; returns the SHA-256 the caller must record.

    The digest is computed HERE from the bytes actually being stored, never accepted from
    the submitter -- a self-declared hash proves nothing about the content.
    """
    if content is None:
        raise EvidenceRejected("evidence content is required")
    if len(content) == 0:
        raise EvidenceRejected("evidence content is empty")
    if len(content) > MAX_EVIDENCE_BYTES:
        raise EvidenceRejected(
            f"evidence is {len(content)} bytes, over the {MAX_EVIDENCE_BYTES} byte limit"
        )
    base_type = (content_type or "").split(";")[0].strip().lower()
    if base_type not in ALLOWED_EVIDENCE_TYPES:
        raise EvidenceRejected(f"content type {content_type!r} is not an allowed evidence type")
    return sha256_hex(content)


class ResultSink(abc.ABC):
    """The scanner's only persistence interface."""

    @abc.abstractmethod
    async def submit_evidence(
        self,
        *,
        scan_id: uuid.UUID,
        tool_run_id: uuid.UUID | None,
        content: bytes,
        content_type: str = "text/plain",
        finding_id: uuid.UUID | None = None,
        execution_token: uuid.UUID | None = None,
        tool_name: str | None = None,
        fingerprint: str | None = None,
    ) -> dict:
        """Persist evidence for `scan_id`. Returns {"uri":..., "sha256":...}.

        `tool_name` lets the CONTROL PLANE re-parse the raw output into vulnerability
        findings with the registry's own parser; `execution_token` fences the write against
        a superseded lease. Both are optional in the signature so the in-process sink and
        existing local callers are unaffected.

        `fingerprint` names the FINDING a screenshot belongs to. The execution plane cannot
        resolve a `vulnerability.id` (it holds no database credential), so it sends the
        stable identity instead and the control plane resolves it against the findings IT
        parsed -- an unknown fingerprint therefore attaches to nothing. Optional for the
        same reason as the others: raw-output evidence never carries one.
        """

    async def submit_tool_started(
        self, *, scan_id: uuid.UUID, tool_run_id: uuid.UUID, tool_name: str,
        execution_token: uuid.UUID | None = None, started_at=None,
    ) -> dict:
        """Announce that a tool has STARTED, before it runs.

        Progress, not outcome: it opens the ToolRun row as `running` with no
        `completed_at`, so the UI can show a live elapsed counter instead of jumping
        straight from 'waiting' to 'completed'. Every caller must treat a failure here as
        cosmetic -- see the executor, which swallows it.

        Not abstract, and returns an empty dict by default: an existing sink that predates
        progress reporting stays valid and simply announces nothing, exactly as
        `submit_tool_result` is non-abstract beside it.
        """
        return {}

    async def submit_tool_result(
        self, *, scan_id: uuid.UUID, tool_run_id: uuid.UUID, status: str, findings: list,
        tool_name: str | None = None, execution_token: uuid.UUID | None = None,
        exit_code: int | None = None, error_message: str | None = None,
        started_at=None, effective_command: str | None = None, timed_out: bool | None = None,
    ) -> dict:
        """Persist one tool run's outcome.

        `started_at` is when the tool actually BEGAN, as observed by whoever ran it. It is
        optional so an older worker still submits successfully (the manager falls back to
        its previous behaviour), but without it a remote run cannot report a real duration.

        `effective_command` (Prompt 10) is the exact, reconstructible command line the tool
        ran with -- never a secret; scan.config carries only tuning knobs and no runner ever
        takes a credential as a CLI argument. `timed_out` is whether the tool's own
        wall-clock budget was exceeded. Both optional so an older worker still submits
        successfully; the manager then simply cannot populate ToolRun.effective_command/
        .timed_out for that submission, exactly as it already cannot for `started_at`.

        Base implementation returns an empty dict rather than leaving the body empty: it is
        deliberately NOT abstract (see submit_tool_started above), and an empty non-abstract
        body is what mypy's `empty-body` check rejects.
        """
        return {}


class LocalResultSink(ResultSink):
    """Direct-write sink: today's behaviour, unchanged.

    Used by the control plane (where holding these credentials is legitimate) and by the
    test suite. It is NOT what the isolated execution worker gets.
    """

    def __init__(self, workspace_id: uuid.UUID | None = None) -> None:
        self.workspace_id = workspace_id

    async def submit_evidence(
        self, *, scan_id, tool_run_id, content, content_type="text/plain", finding_id=None,
        execution_token=None, tool_name=None, fingerprint=None,
    ) -> dict:
        from apps.api.scanner_engine import evidence_store

        digest = validate_evidence(content, content_type)
        # Preserves the existing storage call and its screenshot/raw-output semantics.
        # Uploads the BYTES only: on this path the orchestrator writes the Evidence ROW
        # itself, and writing it here as well would duplicate every local row. The manager
        # path, whose caller writes no row, adds it in the endpoint instead.
        #
        # An IMAGE goes through store_screenshot, and that split is required rather than
        # cosmetic: store_raw_output writes the fixed key `tool-runs/<id>/raw-output.txt`,
        # so routing a PNG through it would overwrite that tool run's actual log with image
        # bytes AND hand the report a .txt URI. store_screenshot keys by content checksum
        # (`vulnerabilities/<id>/screenshot-<sha16>.png`), which also makes a re-capture of
        # an unchanged page idempotent instead of accumulating near-duplicate objects.
        #
        # Keyed by tool_run here rather than by vulnerability id, because neither this sink
        # nor its execution-plane caller can resolve one -- the manager performs the
        # finding association after the bytes are stored.
        base_type = (content_type or "").split(";")[0].strip().lower()
        if base_type == "image/png":
            uri, stored_hash = evidence_store.store_screenshot(
                tool_run_id or scan_id, content
            )
        else:
            uri, stored_hash = evidence_store.store_raw_output(
                tool_run_id or scan_id, content, content_type
            )
        return {"uri": uri, "sha256": stored_hash or digest}

    async def submit_tool_started(
        self, *, scan_id, tool_run_id, tool_name, execution_token=None, started_at=None,
    ) -> dict:
        # No-op: the in-process orchestrator ALREADY inserts its ToolRun row with
        # status='running' before launching the tool, so this path has shown a live
        # elapsed counter all along. Announcing again here would duplicate that row.
        return {"scan_id": str(scan_id), "tool_run_id": str(tool_run_id), "status": "running"}

    async def submit_tool_result(
        self, *, scan_id, tool_run_id, status, findings,
        tool_name=None, execution_token=None, exit_code=None, error_message=None,
        started_at=None, effective_command=None, timed_out=None,
    ) -> dict:
        # `started_at`/`effective_command`/`timed_out` are accepted and ignored here: the
        # in-process orchestrator writes all of this itself directly onto the ToolRun row
        # (orchestrator._run_single_tool sets .effective_command/.timed_out already), so
        # there is nothing for this no-op to fix.
        #
        # The orchestrator already persists tool runs/findings in-process on this path;
        # nothing extra is required, so this is a no-op that keeps the interface uniform.
        #
        # This no-op is CORRECT here and was catastrophic when the isolated worker inherited
        # the same assumption through a different sink: that worker holds no database
        # credential, so "the caller already persisted it" was false and nothing wrote the
        # rows. ManagerResultSink therefore POSTs to the control plane rather than returning
        # early -- the asymmetry is deliberate, not an oversight.
        return {"scan_id": str(scan_id), "tool_run_id": str(tool_run_id), "status": status}


class ManagerResultSink(ResultSink):
    """Execution-plane sink: submits through the manager over the dispatch network.

    Holds ONLY the worker's own identity and the manager URL. There is deliberately no
    database session, no S3 client and no credential for either -- which is what lets the
    scanner image drop them entirely (Phase 7). The manager re-derives the workspace from
    the scan row server-side, so a compromised worker cannot direct evidence at another
    tenant no matter what it sends.
    """

    def __init__(self, *, manager_url: str, worker_id: str, token: str, client=None) -> None:
        self.manager_url = manager_url.rstrip("/")
        self.worker_id = worker_id
        self._token = token
        self._client = client  # injectable for tests

    def _headers(self) -> dict:
        return {"X-Worker-Id": self.worker_id, "Authorization": f"Bearer {self._token}"}

    async def _post_once(self, path: str, *, json=None, files=None) -> dict:
        client = self._client
        if client is None:
            import httpx

            async with httpx.AsyncClient(timeout=60.0) as c:
                resp = await c.post(
                    f"{self.manager_url}{path}", headers=self._headers(), json=json, files=files
                )
                resp.raise_for_status()
                return resp.json()
        resp = await client.post(
            f"{self.manager_url}{path}", headers=self._headers(), json=json, files=files
        )
        resp.raise_for_status()
        return resp.json()

    async def _post(self, path: str, *, json=None, files=None) -> dict:
        """POST to the manager, retrying only TRANSIENT failures, a bounded number of times.

        Raises the last exception when retries are exhausted or the failure is permanent --
        the caller decides what a lost submission means. That decision is deliberately NOT
        made here: `submit_tool_started` treats it as cosmetic, `submit_evidence` as
        acceptable data loss, and `submit_tool_result` as a recorded persistence failure
        that still must not stop the scan. A sink that swallowed errors would take that
        choice away from all three.
        """
        last_exc: Exception | None = None
        for attempt in range(1, _POST_MAX_ATTEMPTS + 1):
            try:
                return await self._post_once(path, json=json, files=files)
            except Exception as exc:  # noqa: BLE001 -- re-raised below unless retryable
                last_exc = exc
                if not _is_retryable(exc) or attempt == _POST_MAX_ATTEMPTS:
                    if attempt > 1:
                        logger.warning(
                            "result_sink.post_exhausted path=%s attempts=%d error=%s",
                            path, attempt, f"{type(exc).__name__}: {exc}",
                            extra={"event": "result_sink.post_exhausted", "path": path,
                                   "attempts": attempt},
                        )
                    raise
                delay = _POST_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                delay += random.uniform(0, _POST_BACKOFF_JITTER)
                logger.warning(
                    "result_sink.post_retry path=%s attempt=%d/%d delay=%.2fs error=%s",
                    path, attempt, _POST_MAX_ATTEMPTS, delay,
                    f"{type(exc).__name__}: {exc}",
                    extra={"event": "result_sink.post_retry", "path": path,
                           "attempt": attempt, "max_attempts": _POST_MAX_ATTEMPTS},
                )
                await asyncio.sleep(delay)
        # Unreachable: the loop either returns or raises. Present so the function has no
        # implicit `None` return path if the bounds above are ever edited.
        raise last_exc if last_exc else RuntimeError("post failed without an exception")

    async def submit_evidence(
        self, *, scan_id, tool_run_id, content, content_type="text/plain", finding_id=None,
        execution_token=None, tool_name=None, fingerprint=None,
    ) -> dict:
        # Validated locally first to fail fast and cheaply; the manager validates again,
        # because a compromised worker would skip this.
        digest = validate_evidence(content, content_type)
        import base64

        return await self._post(
            "/v1/evidence",
            json={
                "scan_id": str(scan_id),
                "tool_run_id": str(tool_run_id) if tool_run_id else None,
                "finding_id": str(finding_id) if finding_id else None,
                "content_type": content_type,
                "content_b64": base64.b64encode(content).decode("ascii"),
                "sha256": digest,
                # Fences the write against a superseded lease.
                "execution_token": str(execution_token) if execution_token else None,
                # Names the PARSER the control plane should apply to these bytes. The
                # worker does not send findings -- the manager derives them itself.
                "tool_name": tool_name,
                # Screenshot association. Carries the finding's stable identity, never a
                # vulnerability id: the worker has no database and could not produce one,
                # and the manager only honours a fingerprint its own parse produced.
                "fingerprint": fingerprint,
            },
        )

    async def submit_tool_started(
        self, *, scan_id, tool_run_id, tool_name, execution_token=None, started_at=None,
    ) -> dict:
        return await self._post(
            "/v1/tool-started",
            json={
                "scan_id": str(scan_id),
                "tool_run_id": str(tool_run_id),
                "tool_name": tool_name,
                "execution_token": str(execution_token) if execution_token else None,
                "started_at": started_at.isoformat() if started_at is not None else None,
            },
        )

    async def submit_tool_result(
        self, *, scan_id, tool_run_id, status, findings,
        tool_name=None, execution_token=None, exit_code=None, error_message=None,
        started_at=None, effective_command=None, timed_out=None,
    ) -> dict:
        return await self._post(
            "/v1/tool-results",
            json={
                "scan_id": str(scan_id),
                "tool_run_id": str(tool_run_id),
                "tool_name": tool_name,
                "execution_token": str(execution_token) if execution_token else None,
                "status": status,
                "findings": findings,
                "exit_code": exit_code,
                "error_message": error_message,
                # When the tool actually started. Omitting it from this body was what made
                # the field unreachable end-to-end: the worker can measure the duration and
                # the manager can store it, but only if it crosses the wire here.
                "started_at": started_at.isoformat() if started_at is not None else None,
                # PROMPT 10: the exact command line the tool ran with -- never a secret (see
                # ToolRun.effective_command). Crossing the wire here is what fixes
                # command_hash never being set at all on this path (it was hardcoded "" in
                # scanner_manager/app.py); the manager now derives both the text and its
                # digest from this single field, server-side, the same way it already
                # derives tool_version from the registry rather than trusting the worker.
                "effective_command": effective_command,
                "timed_out": bool(timed_out) if timed_out is not None else None,
            },
        )


_default_sink: ResultSink | None = None


def set_default_sink(sink: ResultSink | None) -> None:
    global _default_sink
    _default_sink = sink


def get_sink(workspace_id: uuid.UUID | None = None) -> ResultSink:
    """The active sink. Defaults to LocalResultSink so existing in-process callers and
    the whole current test suite behave exactly as before."""
    if _default_sink is not None:
        return _default_sink
    return LocalResultSink(workspace_id=workspace_id)
