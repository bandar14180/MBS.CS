import pytest
from fastapi.testclient import TestClient

from apps.api.main import app


@pytest.fixture(scope="session")
def client():
    # Session-scoped and NOT re-created per test module: our async SQLAlchemy
    # engine (apps/api/core/db.py) is a process-wide singleton, and its asyncpg
    # connections are bound to whichever event loop first opened them. Each
    # `with TestClient(app) as c:` spins up its own loop, so two separate
    # TestClient instances in the same pytest run means the second one's first
    # request reuses a pooled connection from the first's (now-closed) loop --
    # "Future attached to a different loop". One fixture for the whole session
    # keeps everything on a single loop.
    with TestClient(app) as c:
        yield c
