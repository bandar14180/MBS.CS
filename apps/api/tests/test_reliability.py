"""Unit tests for P1 reliability + secret-loading. Pure -- no DB/broker needed."""
import sys
import types


# --- secret loading (P1-9) ---

def test_load_external_secrets_noop_without_backend(monkeypatch) -> None:
    monkeypatch.delenv("SECRETS_BACKEND", raising=False)
    from apps.api.core.secrets import load_external_secrets

    load_external_secrets()  # must not raise or change anything


def test_aws_provider_maps_json_bundle(monkeypatch) -> None:
    from apps.api.core import secrets

    class _FakeClient:
        def get_secret_value(self, SecretId):  # noqa: N803 -- boto3 kwarg name
            return {"SecretString": '{"JWT_SECRET_KEY": "abc", "OPENROUTER_API_KEY": "xyz"}'}

    fake_boto = types.SimpleNamespace(client=lambda *a, **k: _FakeClient())
    monkeypatch.setitem(sys.modules, "boto3", fake_boto)
    out = secrets.AwsSecretsManagerProvider("my-secret", "us-east-1").load()
    assert out == {"JWT_SECRET_KEY": "abc", "OPENROUTER_API_KEY": "xyz"}


def test_external_backend_populates_env_setdefault(monkeypatch) -> None:
    from apps.api.core import secrets

    monkeypatch.setenv("SECRETS_BACKEND", "aws")
    monkeypatch.setenv("AWS_SECRETS_ID", "bundle")
    monkeypatch.delenv("SOME_NEW_SECRET", raising=False)
    monkeypatch.setenv("EXISTING", "keep-me")

    class _FakeClient:
        def get_secret_value(self, SecretId):  # noqa: N803
            return {"SecretString": '{"SOME_NEW_SECRET": "from-aws", "EXISTING": "from-aws"}'}

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: _FakeClient()))
    secrets.load_external_secrets()
    import os

    assert os.environ["SOME_NEW_SECRET"] == "from-aws"   # filled
    assert os.environ["EXISTING"] == "keep-me"           # explicit env wins (setdefault)


# --- Celery reliability config (P1-6) ---

def test_scan_task_has_retry_and_acks_late() -> None:
    from apps.api.celery_app.tasks.scan_tasks import run_scan_task

    assert run_scan_task.max_retries == 3
    assert run_scan_task.acks_late is True


def test_scan_queue_routing_configured() -> None:
    from apps.api.celery_app.worker import celery_app

    assert celery_app.conf.task_acks_late is True
    # MBS.SC: renamed "scans" -> "scans.public" (private scans use per-site queues).
    assert celery_app.conf.task_routes["scans.run_scan"]["queue"] == "scans.public"


def test_record_dlq_is_best_effort(monkeypatch) -> None:
    from apps.api.celery_app.tasks import scan_tasks

    # Point Redis at an unreachable endpoint; _record_dlq must swallow the error.
    monkeypatch.setattr(
        scan_tasks, "get_settings", lambda: types.SimpleNamespace(redis_url="redis://127.0.0.1:1/0")
    )
    scan_tasks._record_dlq("scan-1", RuntimeError("boom"))  # must not raise


class _FakeRedis:
    def __init__(self):
        self.lists: dict = {}

    def rpush(self, k, v):
        self.lists.setdefault(k, []).append(v.encode() if isinstance(v, str) else v)

    def lrange(self, k, a, b):
        return list(self.lists.get(k, []))

    def lrem(self, k, count, val):
        lst = self.lists.get(k, [])
        n = lst.count(val)
        self.lists[k] = [x for x in lst if x != val]
        return n

    def llen(self, k):
        return len(self.lists.get(k, []))

    def delete(self, k):
        self.lists.pop(k, None)

    def ltrim(self, k, a, b):
        pass


def test_dlq_inspect_replay_remove(monkeypatch) -> None:
    import json

    from apps.api.celery_app import dlq
    from apps.api.celery_app.tasks import scan_tasks

    fake = _FakeRedis()
    monkeypatch.setattr(dlq, "_redis", lambda: fake)
    fake.rpush(dlq.DLQ_KEY, json.dumps({"scan_id": "s1", "error": "boom", "retries": 3}))
    fake.rpush(dlq.DLQ_KEY, json.dumps({"scan_id": "s2", "error": "bad", "retries": 3}))

    assert len(dlq.inspect()) == 2

    calls: list = []
    monkeypatch.setattr(scan_tasks.run_scan_task, "delay", lambda sid: calls.append(sid))

    # MBS.SC: dlq.replay() re-derives the scan's queue from its row and dispatches with
    # apply_async(args=[scan_id], queue=...) -- so a failed PRIVATE scan is never replayed
    # onto the public queue. `_queue_for_scan_id` is stubbed because these DLQ ids ("s1")
    # are synthetic, not real scan rows: the test is about DLQ bookkeeping, not routing
    # (routing has its own coverage in test_scan_routing/scan_routing.py).
    monkeypatch.setattr(dlq, "_queue_for_scan_id", lambda sid: "scans.public")

    # dlq.replay() enqueues only under the CELERY dispatch model; under the deployed lease
    # model it refuses rather than enqueue onto a queue with no consumer. This test is about
    # the Celery replay mechanism, so opt into it explicitly.
    from apps.api.core.config import get_settings

    monkeypatch.setattr(get_settings(), "celery_scan_dispatch_enabled", True, raising=False)

    def _fake_apply_async(args=None, kwargs=None, **opts):
        if args:
            calls.append(args[0])

    monkeypatch.setattr(scan_tasks.run_scan_task, "apply_async", _fake_apply_async)
    assert dlq.replay("s1") is True          # re-enqueued once
    assert calls == ["s1"]
    assert [e["scan_id"] for e in dlq.inspect()] == ["s2"]   # s1 removed from DLQ
    assert dlq.replay("missing") is False    # nothing to replay

    assert dlq.remove("s2") == 1
    assert dlq.inspect() == []


def test_get_ai_client_accepts_model_override(monkeypatch) -> None:
    from apps.api.ai_agent.providers import factory
    from apps.api.core.config import get_settings

    monkeypatch.setattr(get_settings(), "ai_provider", "local")
    client = factory.get_ai_client("llama3.2:1b")
    assert client.model_version == "llama3.2:1b"
