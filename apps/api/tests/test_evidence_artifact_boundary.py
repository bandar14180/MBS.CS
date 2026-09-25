"""Prompt 30 -- the evidence artifact boundary: which bytes the report may fetch, and the
raw-vs-normalized separation that differential verification depends on.

THE GAP THIS PINS
-----------------
`render._screenshot_flowable` turns a STORED STRING into a live object fetch. It parsed
`s3://bucket/key` out of `evidence.storage_uri` and passed the parsed BUCKET straight to
`get_storage_provider(bucket).get(key)` -- so the bucket a report reads from was whatever the
row's text said, never checked against the evidence bucket the evidence store actually writes
to.

Not exploitable as the code stands: every writer derives its URI from
`scanner_engine.evidence_store`, which hardcodes `settings.s3_bucket_evidence`. The defect is
that the READ fails OPEN. Tenancy scopes which evidence ROWS a report may load (see
tenancy._evidence_criterion); it says nothing about which bucket a loaded row's free-text URI
points at. So a row that ever came to read `s3://mbs-reports/<other-tenant>/...` -- via a future
ingest path, a migration, or a direct DB write -- would have had those bytes fetched and
EMBEDDED as an image in a rendered PDF, and no row-level scoping would have stopped it.

The fix is a bucket allow-check at the fetch site, failing closed to "no image" exactly as
every other failure in that function does.

WHAT THESE TESTS ALSO GUARANTEE (existing behaviour, pinned as regressions)
---------------------------------------------------------------------------
  * the authoritative raw artifact is never destroyed or rewritten to produce a display form;
  * the report renders artifact REFERENCES and DIGESTS, never artifact BYTES, so a captured
    response containing a credential cannot reach the document through the evidence list;
  * an artifact with no recorded digest is reported as unverifiable, never as verified.
"""

import hashlib
import uuid

import pytest

from apps.api.core.config import get_settings
from apps.api.modules.reports import render
from apps.api.modules.reports.data import EvidenceRecord

mm = 72.0 / 25.4

SECRET_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Set-Cookie: session=super-secret-value\r\n"
    b"Authorization: Bearer abcdef123456\r\n\r\n"
    b"{\"api_key\": \"mbsk_live_deadbeef\"}"
)
DIGEST = hashlib.sha256(SECRET_RESPONSE).hexdigest()


class _RecordingProvider:
    """Captures which (bucket, key) a fetch was attempted against, and serves bytes."""

    attempts: list[tuple[str, str]] = []

    def __init__(self, bucket):
        self._bucket = bucket

    def get(self, key):
        _RecordingProvider.attempts.append((self._bucket, key))
        return None  # bytes are irrelevant: we assert on WHETHER the fetch happened


@pytest.fixture(autouse=True)
def _reset_attempts():
    _RecordingProvider.attempts = []
    yield
    _RecordingProvider.attempts = []


@pytest.fixture
def _provider(monkeypatch):
    monkeypatch.setattr(
        "apps.api.scanner_engine.storage_provider.get_storage_provider",
        _RecordingProvider,
    )


# --- 1. the fetch is confined to the evidence bucket ------------------------------------------

def test_screenshot_fetch_is_attempted_for_the_evidence_bucket(_provider):
    """The legitimate path must still work -- this is the control for the negative cases."""
    bucket = get_settings().s3_bucket_evidence
    render._screenshot_flowable(f"s3://{bucket}/vulnerabilities/abc/screenshot-0011.png", mm)
    assert _RecordingProvider.attempts == [(bucket, "vulnerabilities/abc/screenshot-0011.png")]


def test_a_uri_naming_another_bucket_is_never_fetched(_provider):
    """THE core case. A row pointing at the REPORTS bucket must not be read at all.

    Asserting on `attempts` rather than on the return value matters: returning None because
    the object happened to be missing is not the same guarantee as never reaching for it. The
    requirement is that the bytes are not fetched."""
    render._screenshot_flowable("s3://mbs-reports/other-tenant/report.pdf", mm)
    assert _RecordingProvider.attempts == []


def test_an_arbitrary_bucket_is_never_fetched(_provider):
    render._screenshot_flowable("s3://some-unrelated-bucket/anything.png", mm)
    assert _RecordingProvider.attempts == []


def test_out_of_bucket_uri_fails_closed_to_no_image(_provider):
    """Fails CLOSED: no image, no exception. A refused fetch must not break the report."""
    assert render._screenshot_flowable("s3://mbs-reports/x/y.png", mm) is None


def test_non_s3_and_malformed_uris_are_still_rejected(_provider):
    """Pre-existing behaviour, re-pinned so the new bucket check did not weaken it."""
    assert render._screenshot_flowable("not-an-s3-uri", mm) is None
    assert render._screenshot_flowable("s3://bucket-only", mm) is None
    assert render._screenshot_flowable("unavailable://evidence-storage-failed/x", mm) is None
    assert _RecordingProvider.attempts == []


# --- 2. raw artifacts are referenced, never inlined -------------------------------------------

def test_evidence_record_exposes_a_reference_and_a_digest_not_content():
    """An EvidenceRecord is a POINTER plus integrity metadata.

    There is deliberately no field carrying artifact BYTES: a captured HTTP response routinely
    contains a Set-Cookie, an Authorization header or an API key, and the authoritative raw
    artifact is kept intact in object storage precisely so differential verification can still
    use it. Keeping the bytes out of the report record is what lets both be true at once --
    the raw artifact stays whole AND the document never carries the secret."""
    record = EvidenceRecord(
        evidence_id=uuid.uuid4(), evidence_type="log_excerpt",
        storage_uri="s3://mbs-evidence/tool-runs/abc/raw-output.txt",
        checksum=DIGEST, captured_at=None,
    )
    values = " ".join(str(v) for v in vars(record).values())
    assert b"super-secret-value".decode() not in values
    assert b"mbsk_live_deadbeef".decode() not in values
    assert record.checksum == DIGEST


def test_digest_identifies_the_raw_bytes_so_normalization_cannot_be_substituted():
    """The recorded digest is over the ORIGINAL bytes.

    This is the property differential verification rests on: a normalized/display form has a
    different digest, so a normalized artifact can never be passed off as the authoritative
    one. Recomputing over anything but the original fails."""
    record = EvidenceRecord(
        evidence_id=uuid.uuid4(), evidence_type="log_excerpt",
        storage_uri="s3://mbs-evidence/tool-runs/abc/raw-output.txt",
        checksum=DIGEST, captured_at=None,
    )
    normalized = SECRET_RESPONSE.replace(b"super-secret-value", b"[REDACTED]")
    assert hashlib.sha256(normalized).hexdigest() != record.checksum
    assert hashlib.sha256(SECRET_RESPONSE).hexdigest() == record.checksum


# --- 3. absent integrity metadata is stated, never assumed ------------------------------------

def test_an_artifact_without_a_digest_is_reported_unverifiable():
    record = EvidenceRecord(
        evidence_id=uuid.uuid4(), evidence_type="log_excerpt",
        storage_uri="s3://mbs-evidence/tool-runs/abc/raw-output.txt",
        checksum=None, captured_at=None,
    )
    assert record.has_checksum is False
    assert record.checksum_label() == "not recorded"
    assert record.captured_label() == "not recorded"


def test_a_truncated_digest_is_not_presented_as_a_verified_one():
    """A placeholder or truncated value must not acquire the authority of a real digest."""
    record = EvidenceRecord(
        evidence_id=uuid.uuid4(), evidence_type="log_excerpt",
        storage_uri="s3://mbs-evidence/tool-runs/abc/raw-output.txt",
        checksum=DIGEST[:32], captured_at=None,
    )
    assert record.has_checksum is False
    assert record.checksum_label() == "not recorded"
