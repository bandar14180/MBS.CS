"""Phase 5.1 -- storage delete primitive (StorageProvider.delete / .delete_prefix).

Pure unit tests: a fake boto3 client is injected via S3StorageProvider._client, so no real
MinIO/S3/network is touched (same seam style as test_interfaces.py). Covers success, prefix
deletion + pagination, idempotent missing-object handling, the unsafe-path / whole-bucket
guards, and genuine-failure propagation.
"""
import pytest
from botocore.exceptions import ClientError

from apps.api.scanner_engine.storage_provider import S3StorageProvider


class _FakePaginator:
    def __init__(self, client: "_FakeS3", page_size: int = 2):
        self._client = client
        self._page_size = page_size

    def paginate(self, Bucket, Prefix):  # noqa: N803 (boto kwarg names)
        matched = sorted(k for k in self._client.objects if k.startswith(Prefix))
        if not matched:
            yield {}  # a page with no "Contents" -> exercises the empty-page branch
            return
        for i in range(0, len(matched), self._page_size):
            yield {"Contents": [{"Key": k} for k in matched[i : i + self._page_size]]}


class _FakeS3:
    """Minimal in-memory stand-in for the boto3 S3 client (delete paths only)."""

    def __init__(self, objects: dict[str, bytes] | None = None):
        self.objects = dict(objects or {})
        self.deleted: list[str] = []
        self.delete_object_error: ClientError | None = None

    def delete_object(self, Bucket, Key):  # noqa: N803
        if self.delete_object_error is not None:
            raise self.delete_object_error
        self.deleted.append(Key)
        self.objects.pop(Key, None)  # missing key is fine (idempotent)
        return {}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return _FakePaginator(self)

    def delete_objects(self, Bucket, Delete):  # noqa: N803
        keys = [o["Key"] for o in Delete["Objects"]]
        for k in keys:
            self.objects.pop(k, None)
            self.deleted.append(k)
        return {"Deleted": [{"Key": k} for k in keys]}


def _provider(monkeypatch, fake: _FakeS3) -> S3StorageProvider:
    provider = S3StorageProvider(bucket="mbs-evidence")
    monkeypatch.setattr(provider, "_client", lambda: fake)
    return provider


# --- delete: success + idempotency ---------------------------------------------------------

def test_delete_removes_object(monkeypatch):
    fake = _FakeS3({"reports/a.pdf": b"x"})
    provider = _provider(monkeypatch, fake)

    provider.delete("reports/a.pdf")

    assert "reports/a.pdf" not in fake.objects
    assert fake.deleted == ["reports/a.pdf"]


def test_delete_missing_object_is_idempotent(monkeypatch):
    fake = _FakeS3()  # empty store
    provider = _provider(monkeypatch, fake)

    # Deleting something that isn't there must not raise -- and doing it twice is still fine.
    provider.delete("reports/ghost.pdf")
    provider.delete("reports/ghost.pdf")


def test_delete_treats_nosuchkey_clienterror_as_success(monkeypatch):
    fake = _FakeS3()
    fake.delete_object_error = ClientError({"Error": {"Code": "NoSuchKey"}}, "DeleteObject")
    provider = _provider(monkeypatch, fake)

    provider.delete("reports/gone.pdf")  # backend surfaced 'missing' -> swallowed, no raise


# --- delete_prefix: bulk + pagination + no-match -------------------------------------------

def test_delete_prefix_removes_all_matching_and_counts(monkeypatch):
    fake = _FakeS3(
        {
            "tool-runs/s1/a.txt": b"1",
            "tool-runs/s1/b.txt": b"2",
            "tool-runs/s1/c.txt": b"3",  # 3 under prefix forces >1 page (page_size=2)
            "tool-runs/s2/keep.txt": b"9",  # different prefix -> must survive
        }
    )
    provider = _provider(monkeypatch, fake)

    deleted = provider.delete_prefix("tool-runs/s1/")

    assert deleted == 3
    assert set(fake.objects) == {"tool-runs/s2/keep.txt"}


def test_delete_prefix_no_match_returns_zero(monkeypatch):
    fake = _FakeS3({"reports/a.pdf": b"x"})
    provider = _provider(monkeypatch, fake)

    assert provider.delete_prefix("tool-runs/does-not-exist/") == 0
    assert "reports/a.pdf" in fake.objects  # nothing collateral removed


# --- security guards -----------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["", "   ", "/etc/passwd", "../secret", "a\\b", "x\x00y"])
def test_delete_rejects_unsafe_key(monkeypatch, bad):
    fake = _FakeS3()
    provider = _provider(monkeypatch, fake)
    with pytest.raises(ValueError):
        provider.delete(bad)
    assert fake.deleted == []  # never reached the backend


@pytest.mark.parametrize("bad", ["", "   ", "/", "///", "../", "a\\b", "x\x00y"])
def test_delete_prefix_refuses_unsafe_or_bucket_wide_prefix(monkeypatch, bad):
    # The empty / all-slash cases are the important ones: they must NOT wipe the bucket.
    fake = _FakeS3({"reports/a.pdf": b"x", "tool-runs/s1/a.txt": b"y"})
    provider = _provider(monkeypatch, fake)
    with pytest.raises(ValueError):
        provider.delete_prefix(bad)
    assert set(fake.objects) == {"reports/a.pdf", "tool-runs/s1/a.txt"}  # untouched


# --- genuine failure propagation -----------------------------------------------------------

def test_delete_propagates_real_storage_failure(monkeypatch):
    fake = _FakeS3({"reports/a.pdf": b"x"})
    fake.delete_object_error = ClientError({"Error": {"Code": "AccessDenied"}}, "DeleteObject")
    provider = _provider(monkeypatch, fake)

    with pytest.raises(ClientError):
        provider.delete("reports/a.pdf")  # a non-missing error must surface, not be swallowed
