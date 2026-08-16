"""W1 -- worker prefork metrics aggregation.

Proves that with PROMETHEUS_MULTIPROC_DIR set, a metric incremented in a SEPARATE process is
aggregated by MultiProcessCollector -- i.e. the mechanism metrics.py relies on actually exports a
child process's counts (the exact thing broken today, where prefork children's counters never reach
the MainProcess :9100 endpoint). A subprocess stands in for a prefork child so the parent test's own
registry is never mutated.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

import apps.api.core.observability as obs

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(not obs._PROM, reason="prometheus_client not installed")
def test_multiprocess_aggregates_a_child_increment(tmp_path):
    # A child process: enable multiprocess mode (env set BEFORE import), record one scan success.
    child = "import apps.api.core.observability as o; o.record_scan_result('completed', 1.0)"
    env = {**os.environ, "PROMETHEUS_MULTIPROC_DIR": str(tmp_path)}
    subprocess.run([sys.executable, "-c", child], env=env, cwd=str(REPO_ROOT), check=True)

    # The child must have written per-process metric files into the shared dir.
    assert any(p.suffix == ".db" for p in tmp_path.iterdir()), "child wrote no multiprocess files"

    # The parent aggregates the dir and must SEE the child's increment (this is what the worker
    # :9100 endpoint does via MultiProcessCollector; without W1 the value would be absent).
    from prometheus_client import CollectorRegistry, multiprocess

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry, path=str(tmp_path))
    value = registry.get_sample_value("mbs_scan_success_total")
    assert value == 1.0, f"expected the child's aggregated increment (1.0), got {value!r}"


@pytest.mark.skipif(not obs._PROM, reason="prometheus_client not installed")
def test_multiprocess_dir_is_populated_by_multiple_processes(tmp_path):
    """Two separate processes each increment; the aggregate is the SUM (proves cross-process
    aggregation, not last-writer-wins)."""
    child = "import apps.api.core.observability as o; o.record_scan_result('completed', 1.0)"
    env = {**os.environ, "PROMETHEUS_MULTIPROC_DIR": str(tmp_path)}
    for _ in range(2):
        subprocess.run([sys.executable, "-c", child], env=env, cwd=str(REPO_ROOT), check=True)

    from prometheus_client import CollectorRegistry, multiprocess

    registry = CollectorRegistry()
    multiprocess.MultiProcessCollector(registry, path=str(tmp_path))
    assert registry.get_sample_value("mbs_scan_success_total") == 2.0
