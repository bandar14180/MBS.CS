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
    assert celery_app.conf.task_routes["scans.run_scan"]["queue"] == "scans"


def test_record_dlq_is_best_effort(monkeypatch) -> None:
    from apps.api.celery_app.tasks import scan_tasks

    # Point Redis at an unreachable endpoint; _record_dlq must swallow the error.
    monkeypatch.setattr(
        scan_tasks, "get_settings", lambda: types.SimpleNamespace(redis_url="redis://127.0.0.1:1/0")
    )
    scan_tasks._record_dlq("scan-1", RuntimeError("boom"))  # must not raise
