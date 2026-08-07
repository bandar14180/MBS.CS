"""Phase 1.6 -- object-storage (MinIO/S3) backup / restore / verify for the DR system.

Every bucket is backed up into ONE archive (objects.tar[.gz]) plus a metadata sidecar
(objects.meta.json) that PRESERVES each object's content-type + user metadata, so a restore
is faithful. The store is an injectable seam (`ObjectStore`) -- `BotoObjectStore` talks to
real S3/MinIO; tests pass an in-memory fake -- so the archive logic is fully unit-testable
without a live MinIO.
"""
import io
import json
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol

OBJECTS_MANIFEST = "objects.meta.json"
_ARCHIVE_GZ = "objects.tar.gz"
_ARCHIVE_PLAIN = "objects.tar"


@dataclass
class ObjMeta:
    bucket: str
    key: str
    size: int = 0
    content_type: str | None = None
    metadata: dict = field(default_factory=dict)


class ObjectStore(Protocol):
    def buckets(self) -> list[str]: ...
    def list_objects(self, bucket: str) -> Iterator[ObjMeta]: ...
    def read_object(self, bucket: str, key: str) -> bytes: ...
    def ensure_bucket(self, bucket: str) -> None: ...
    def write_object(self, bucket: str, key: str, data: bytes, meta: ObjMeta) -> None: ...


class BotoObjectStore:
    """Real S3/MinIO store (portable path-style s3v4), reusing the app's S3_* settings.
    boto3 is imported lazily so importing the DR package never requires it."""

    def __init__(self, settings):
        import boto3
        from botocore.config import Config

        self._buckets = [b for b in (settings.s3_bucket_evidence, settings.s3_bucket_reports) if b]
        self._c = boto3.client(
            "s3",
            endpoint_url=settings.s3_endpoint_url,
            aws_access_key_id=settings.s3_access_key,
            aws_secret_access_key=settings.s3_secret_key,
            region_name=getattr(settings, "s3_region", "us-east-1"),
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    def buckets(self) -> list[str]:
        return list(self._buckets)

    def list_objects(self, bucket: str) -> Iterator[ObjMeta]:
        for page in self._c.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                head = self._c.head_object(Bucket=bucket, Key=obj["Key"])
                yield ObjMeta(bucket, obj["Key"], obj.get("Size", 0),
                              head.get("ContentType"), dict(head.get("Metadata") or {}))

    def read_object(self, bucket: str, key: str) -> bytes:
        return self._c.get_object(Bucket=bucket, Key=key)["Body"].read()

    def ensure_bucket(self, bucket: str) -> None:
        try:
            self._c.head_bucket(Bucket=bucket)
        except Exception:  # noqa: BLE001 -- absent -> create
            self._c.create_bucket(Bucket=bucket)

    def write_object(self, bucket: str, key: str, data: bytes, meta: ObjMeta) -> None:
        extra: dict = {}
        if meta.content_type:
            extra["ContentType"] = meta.content_type
        if meta.metadata:
            extra["Metadata"] = meta.metadata
        self._c.put_object(Bucket=bucket, Key=key, Body=data, **extra)


def archive_path(directory) -> Path:
    """The objects archive in `directory`, whichever compression variant exists."""
    d = Path(directory)
    gz = d / _ARCHIVE_GZ
    return gz if gz.exists() else d / _ARCHIVE_PLAIN


def backup_objects(dest_dir, store: ObjectStore, *, compress: bool = True) -> dict:
    """Stream every object from every bucket into a single tar[.gz] and record a metadata
    manifest. Returns {archive, count}."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    archive = dest / (_ARCHIVE_GZ if compress else _ARCHIVE_PLAIN)
    manifest: dict = {"buckets": store.buckets(), "objects": []}
    count = 0
    with tarfile.open(archive, "w:gz" if compress else "w") as tar:
        for bucket in store.buckets():
            for om in store.list_objects(bucket):
                data = store.read_object(bucket, om.key)
                info = tarfile.TarInfo(name=f"{bucket}/{om.key}")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
                manifest["objects"].append({
                    "bucket": bucket, "key": om.key, "size": len(data),
                    "content_type": om.content_type, "metadata": om.metadata,
                })
                count += 1
    manifest["count"] = count
    (dest / OBJECTS_MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return {"archive": str(archive), "count": count}


def restore_objects(src_dir, store: ObjectStore) -> int:
    """Upload every archived object back to its bucket, re-applying preserved metadata.
    Creates buckets as needed. Returns the number of objects restored."""
    src = Path(src_dir)
    manifest = json.loads((src / OBJECTS_MANIFEST).read_text(encoding="utf-8"))
    meta_by = {(o["bucket"], o["key"]): o for o in manifest["objects"]}
    for bucket in {o["bucket"] for o in manifest["objects"]}:
        store.ensure_bucket(bucket)
    restored = 0
    with tarfile.open(archive_path(src), "r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            bucket, _, key = member.name.partition("/")
            data = tar.extractfile(member).read()
            m = meta_by.get((bucket, key), {})
            store.write_object(
                bucket, key, data,
                ObjMeta(bucket, key, len(data), m.get("content_type"), m.get("metadata") or {}),
            )
            restored += 1
    return restored


def verify_objects_archive(dest_dir) -> bool:
    """Corruption detection for the object archive: manifest + archive present, the tar
    (and its gzip layer) fully readable, and the member count matches the manifest."""
    dest = Path(dest_dir)
    man = dest / OBJECTS_MANIFEST
    archive = archive_path(dest)
    if not man.exists() or not archive.exists():
        return False
    try:
        manifest = json.loads(man.read_text(encoding="utf-8"))
        with tarfile.open(archive, "r:*") as tar:
            files = 0
            for member in tar.getmembers():
                if member.isfile():
                    tar.extractfile(member).read()  # raises on gzip/tar CRC corruption
                    files += 1
        return files == manifest.get("count", -1)
    except Exception:  # noqa: BLE001 -- any read/parse error == corrupt/invalid
        return False
