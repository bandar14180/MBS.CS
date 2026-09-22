"""Katana runner: invocation, GOMEMLIMIT sizing, parsing, and failure classification.

WHY THIS FILE EXISTS. The UI reported `Katana failed (17.2s)` on every scan. The cause was
NOT a timeout (the runner's own budget for that run was 585s, and its timeout path returns
exit code -1), not the arguments, and not the parser. katana is a Go binary, and Go's garbage
collector sizes the heap from /proc/meminfo -- the whole VM, 7792 MiB here -- while the worker
container is confined to a 2048 MiB cgroup. The GC aimed at a target the cgroup would never
permit, so the kernel OOM-killed katana mid-crawl: exit code -9, after 14-17s, with the
cgroup's oom_kill counter incrementing once per run. Partial stdout recovered from the failed
runs contained valid crawled URLs, proving the crawl itself worked.

The fix sets GOMEMLIMIT from the REAL cgroup limit so the GC collects while headroom remains.
These tests pin the sizing rule, the invocation, the parser, and the exit-code handling.

Fully deterministic: subprocesses are faked, no network, no real katana binary.
"""

import asyncio
import time

import pytest

from apps.api.scanner_engine.tool_runners import katana_runner
from apps.api.scanner_engine.tool_runners import base
from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput, classify_run


# --- Fakes --------------------------------------------------------------------------------

class _FakeStream:
    def __init__(self, chunks: list[bytes]):
        self._chunks = list(chunks)

    async def read(self, _n: int = -1) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _FakeStdin:
    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakeProc:
    def __init__(self, stdout=(), stderr=(), returncode=0):
        self.stdout = _FakeStream(list(stdout))
        self.stderr = _FakeStream(list(stderr))
        self.stdin = _FakeStdin()
        self._returncode = returncode
        self.returncode = None

    async def wait(self):
        if self.returncode is None:
            self.returncode = self._returncode
        return self.returncode

    def kill(self):
        self.returncode = -9


def _run_katana(monkeypatch, *, stdout=(), stderr=(), returncode=0, config=None):
    """Drive KatanaRunner.run() against a faked subprocess; return (RawToolOutput, captured)."""
    captured: dict = {}

    async def _fake_exec(*command, **kwargs):
        captured["command"] = list(command)
        captured["env"] = kwargs.get("env")
        proc = _FakeProc(stdout=stdout, stderr=stderr, returncode=returncode)
        captured["proc"] = proc
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)

    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://target.example", config or {}, []))
    return raw, captured


# ============================ 1. GOMEMLIMIT sizing ========================================

def test_gomemlimit_is_a_fraction_of_the_real_cgroup_limit() -> None:
    """THE fix. 2 GiB cgroup -> a heap ceiling well under it, leaving non-heap headroom."""
    assert katana_runner.compute_gomemlimit_mib(2 * 1024**3) == 716


def test_gomemlimit_is_none_when_the_cgroup_is_unlimited() -> None:
    """No cap means nothing to protect against; forcing one would only slow the crawl."""
    assert katana_runner.compute_gomemlimit_mib(None) is None


def test_gomemlimit_clamps_at_both_ends() -> None:
    assert katana_runner.compute_gomemlimit_mib(100 * 1024**2) == 256      # floor
    assert katana_runner.compute_gomemlimit_mib(32 * 1024**3) == 4096      # ceiling


def test_cgroup_reader_returns_none_for_literal_max(monkeypatch, tmp_path) -> None:
    """`memory.max` reads the string "max" when unconstrained -- must not crash or return 0."""
    f = tmp_path / "memory.max"
    f.write_text("max")
    monkeypatch.setattr("builtins.open", lambda *a, **k: f.open())
    assert katana_runner._cgroup_memory_max_bytes() is None


def test_cgroup_reader_returns_none_when_file_absent(monkeypatch) -> None:
    """cgroup v1 / non-containerised hosts have no memory.max: opt out, never raise."""
    def _boom(*_a, **_k):
        raise OSError("no such file")
    monkeypatch.setattr("builtins.open", _boom)
    assert katana_runner._cgroup_memory_max_bytes() is None


def test_env_carries_gomemlimit_when_capped(monkeypatch) -> None:
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: 2 * 1024**3)
    env = katana_runner._katana_env()
    assert env["GOMEMLIMIT"] == "716MiB"
    # GOGC deliberately left alone -- see the module docstring.
    assert "GOGC" not in env or env.get("GOGC") == ""


def test_env_omits_gomemlimit_when_uncapped(monkeypatch) -> None:
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: None)
    assert "GOMEMLIMIT" not in katana_runner._katana_env()


def test_env_is_passed_to_the_subprocess(monkeypatch) -> None:
    """Sizing is worthless if the env never reaches katana -- this is the wiring check."""
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: 2 * 1024**3)
    _raw, cap = _run_katana(monkeypatch, stdout=[b"https://target.example/a\n"])
    assert cap["env"] is not None
    assert cap["env"]["GOMEMLIMIT"] == "716MiB"


# ============================ 2. Arguments / input ========================================

def test_command_uses_the_installed_versions_flags(monkeypatch) -> None:
    """Every flag here was verified present in the installed katana 1.7.0 `-h` output."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"https://target.example/a\n"])
    cmd = cap["command"]
    assert cmd[0] == "katana"
    for flag in ("-silent", "-no-color", "-depth", "-js-crawl",
                 "-field-scope", "-concurrency", "-parallelism", "-rate-limit", "-timeout"):
        assert flag in cmd, f"{flag} missing from katana invocation"
    # JS crawling must stay on: it is what surfaces API endpoints for the DAST runner.
    assert "-js-crawl" in cmd
    # -jsluice is OPT-IN (JSLUICE_DEFAULT is False): measured at 3.6-3.8 GiB peak for ONE URL
    # on real targets vs ~75 MiB for ~2465 URLs without it. Absent from argv unless enabled.
    assert "-jsluice" not in cmd
    assert cmd[cmd.index("-field-scope") + 1] == "fqdn"


def test_targets_are_fed_on_stdin_not_argv(monkeypatch) -> None:
    """katana takes its target list on stdin; a target leaking into argv would change scope.

    web_targets() expands a bare host into its http:// and https:// forms, so stdin carries a
    newline-separated list -- assert on membership, not on one exact string.
    """
    _raw, cap = _run_katana(monkeypatch, stdout=[b"https://target.example/a\n"])
    written = cap["proc"].stdin.written.decode()
    assert "https://target.example" in written.split("\n")
    assert cap["proc"].stdin.closed is True
    # No target may appear in argv -- scope is controlled via stdin + -field-scope.
    for line in written.split("\n"):
        assert line not in cap["command"]


def test_crawl_rate_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"], config={"crawl_rate": 25})
    cmd = cap["command"]
    assert cmd[cmd.index("-rate-limit") + 1] == "25"


def test_response_size_is_capped_below_katanas_default(monkeypatch) -> None:
    """Attacks the memory problem at source: katana's own default is 4 MiB per response, and
    -jsluice (documented by katana as "memory intensive") holds whole JS bodies."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert "-max-response-size" in cmd
    assert int(cmd[cmd.index("-max-response-size") + 1]) == 1024 * 1024


def test_concurrency_is_bounded_for_jsluice_memory(monkeypatch) -> None:
    """Concurrency is the dominant memory multiplier: at 10 the cgroup grew ~226 MiB/s and was
    OOM-killed. Coverage is unchanged -- every URL is still crawled, just fewer at a time."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert cmd[cmd.index("-concurrency") + 1] == "3"


def test_parallelism_is_set_explicitly(monkeypatch) -> None:
    """THE OOM fix. `-parallelism` bounds concurrent INPUTS (targets); `-concurrency` bounds
    fetchers WITHIN one input. Omitting it left katana on its own default of 10, so a
    44-target scan ran ten crawls at once and the cgroup OOM killer took the process
    (exit -9 at 112.6s, memory.peak == memory.max == 4096 MiB). Every 1-target run survived;
    every multi-target run died -- the flag must therefore be passed EXPLICITLY, never
    defaulted."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert "-parallelism" in cmd, "-parallelism missing: katana would default to 10"
    assert cmd[cmd.index("-parallelism") + 1] == "2"


def test_parallelism_and_concurrency_are_separate_axes(monkeypatch) -> None:
    """Guards against the two being conflated again: they are different knobs and both must
    be present, each with its own value."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert cmd[cmd.index("-parallelism") + 1] == "2"
    assert cmd[cmd.index("-concurrency") + 1] == "3"


def test_parallelism_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"], config={"crawl_parallelism": 1})
    cmd = cap["command"]
    assert cmd[cmd.index("-parallelism") + 1] == "1"


def test_concurrency_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"], config={"crawl_concurrency": 6})
    cmd = cap["command"]
    assert cmd[cmd.index("-concurrency") + 1] == "6"


def test_crawl_is_bounded_so_katana_exits_on_its_own(monkeypatch) -> None:
    """Without this katana crawled until the 585s budget expired (29,828 URLs, exit -1) and
    the parser kept only MAX_URLS of them. Bounding the crawl lets it finish with exit 0."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert "-max-domain-pages" in cmd
    pages = int(cmd[cmd.index("-max-domain-pages") + 1])
    # Must exceed MAX_URLS: one page can emit several URLs, and the parser also dedupes.
    assert pages > katana_runner.MAX_URLS


def test_max_domain_pages_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"], config={"max_domain_pages": 750})
    cmd = cap["command"]
    assert cmd[cmd.index("-max-domain-pages") + 1] == "750"


def test_crawl_duration_stops_katana_before_the_runner_timeout(monkeypatch) -> None:
    """The bound that actually yields exit 0. It MUST be below the runner's own budget --
    if it were not, run_with_timeout would fire first and the run would be exit -1 again."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"x\n"])
    cmd = cap["command"]
    assert "-crawl-duration" in cmd
    value = cmd[cmd.index("-crawl-duration") + 1]
    assert value.endswith("s")
    assert int(value[:-1]) < katana_runner.compute_timeout(1, 2, js_crawl=True)


def test_crawl_duration_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(
        monkeypatch, stdout=[b"x\n"], config={"crawl_duration_seconds": 120}
    )
    cmd = cap["command"]
    assert cmd[cmd.index("-crawl-duration") + 1] == "120s"


def test_response_size_is_configurable(monkeypatch) -> None:
    _raw, cap = _run_katana(
        monkeypatch, stdout=[b"x\n"], config={"max_response_bytes": 2 * 1024 * 1024}
    )
    cmd = cap["command"]
    assert cmd[cmd.index("-max-response-size") + 1] == str(2 * 1024 * 1024)


def test_no_web_targets_short_circuits(monkeypatch) -> None:
    """No reachable web target must not spawn a process at all."""
    called = False

    async def _fake_exec(*_a, **_k):
        nonlocal called
        called = True
        raise AssertionError("must not spawn katana without targets")

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(katana_runner, "web_targets", lambda *_a, **_k: [])
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://target.example", {}, []))
    assert called is False
    assert raw.exit_code == -1
    assert "no web targets" in raw.stderr


# ============================ 3. Parsing ==================================================

def test_parse_extracts_urls_and_flags_params() -> None:
    raw = RawToolOutput(
        command="katana",
        stdout=(
            "https://t.example/\n"
            "https://t.example/search?q=1\n"
            "http://t.example/plain\n"
        ),
        stderr="",
        exit_code=0,
    )
    findings = katana_runner.KatanaRunner().parse(raw)
    assert [f.value for f in findings] == [
        "https://t.example/", "https://t.example/search?q=1", "http://t.example/plain",
    ]
    assert all(f.asset_type == "url" for f in findings)
    assert all(f.metadata["source"] == "katana" for f in findings)
    by_value = {f.value: f.metadata["has_params"] for f in findings}
    assert by_value["https://t.example/search?q=1"] is True
    assert by_value["https://t.example/"] is False


def test_parse_deduplicates_and_skips_non_urls() -> None:
    raw = RawToolOutput(
        command="katana",
        stdout=(
            "https://t.example/a\n"
            "https://t.example/a\n"          # duplicate
            "   \n"                          # blank
            "[INF] banner noise\n"           # not a URL
            "ftp://t.example/x\n"            # wrong scheme
            "https://t.example/b\n"
        ),
        stderr="",
        exit_code=0,
    )
    findings = katana_runner.KatanaRunner().parse(raw)
    assert [f.value for f in findings] == ["https://t.example/a", "https://t.example/b"]


def test_parse_of_empty_output_is_empty_not_an_error() -> None:
    raw = RawToolOutput(command="katana", stdout="", stderr="", exit_code=0)
    assert katana_runner.KatanaRunner().parse(raw) == []


def test_parse_handles_real_captured_output() -> None:
    """Verbatim lines recovered from the OOM-killed production run (MinIO evidence)."""
    stdout = "\n".join([
        "https://www.lincoln.edu.my",
        "https://www.lincoln.edu.my/wp-includes/js/wp-emoji-loader.min.js",
        "https://www.lincoln.edu.my/wp-json/oembed/1.0/embed?url=https%3A%2F%2Fwww.lincoln.edu.my%2F&",
        "http://www.w3.org/2000/svg",
    ]) + "\n"
    findings = katana_runner.KatanaRunner().parse(
        RawToolOutput(command="katana", stdout=stdout, stderr="", exit_code=0)
    )
    assert len(findings) == 4
    embed = next(f for f in findings if "oembed" in f.value)
    assert embed.metadata["has_params"] is True


# ============================ 4/5. Exit codes, stderr, SIGKILL ============================

def test_clean_exit_returns_zero_and_keeps_stdout(monkeypatch) -> None:
    """stdout is unchanged; stderr is now a PER-TARGET summary rather than katana's raw
    stderr, because one tool run spans one process per target and 44 concatenated stderr
    blobs are not diagnosable. Each target's outcome is reported on its own line."""
    raw, _cap = _run_katana(
        monkeypatch, stdout=[b"https://target.example/a\n"], stderr=[b"[INF] done\n"]
    )
    assert raw.exit_code == 0
    assert "https://target.example/a" in raw.stdout
    assert "one process each" in raw.stderr
    assert "exit=0" in raw.stderr              # every target's outcome is stated


def test_sigkill_is_diagnosed_and_partial_urls_survive(monkeypatch) -> None:
    """THE regression. -9 previously stored a bare exit code with error_message NULL, so the
    UI said "Katana failed" with no reason. The run must still explain itself AND keep its URLs.

    The AGGREGATE code is now -1, not -9: with one process per target, "this process was killed
    from outside" no longer describes the tool run as a whole. The kill stays fully visible per
    target (exit=-9 on that target's summary line), and classify_run still yields `partial`.
    """
    raw, _cap = _run_katana(
        monkeypatch,
        stdout=[b"https://target.example/a\n", b"https://target.example/b\n"],
        returncode=-9,
    )
    assert raw.exit_code == -1
    assert "exit=-9" in raw.stderr
    assert "SIGKILL" in raw.stderr
    assert "OOM" in raw.stderr
    assert "killed" in raw.stderr
    # The crawled URLs must still reach the parser.
    assert len(katana_runner.KatanaRunner().parse(raw)) == 2


def test_sigkill_with_output_classifies_partial_not_failed(monkeypatch) -> None:
    """Contained degradation: usable output keeps the run `partial`, never a silent success."""
    raw, _cap = _run_katana(
        monkeypatch, stdout=[b"https://target.example/a\n"], returncode=-9
    )
    runner = katana_runner.KatanaRunner()
    assert classify_run(runner, raw, produced_findings=True) == "partial"


def test_sigkill_with_no_output_classifies_failed(monkeypatch) -> None:
    raw, _cap = _run_katana(monkeypatch, stdout=[], returncode=-9)
    runner = katana_runner.KatanaRunner()
    assert classify_run(runner, raw, produced_findings=False) == "failed"


def test_nonzero_exit_with_output_is_partial(monkeypatch) -> None:
    """The aggregate is -1 whenever any target did not exit 0; that target's real code is kept
    on its summary line. classify_run's outcome -- `partial` with usable output -- is unchanged."""
    raw, _cap = _run_katana(
        monkeypatch, stdout=[b"https://target.example/a\n"], returncode=2
    )
    assert raw.exit_code == -1
    assert "exit=2" in raw.stderr
    runner = katana_runner.KatanaRunner()
    assert classify_run(runner, raw, produced_findings=True) == "partial"


def test_empty_output_clean_exit_is_completed(monkeypatch) -> None:
    """Exit 0 with nothing crawled is a legitimate 'found nothing', not a failure."""
    raw, _cap = _run_katana(monkeypatch, stdout=[], returncode=0)
    runner = katana_runner.KatanaRunner()
    assert classify_run(runner, raw, produced_findings=False) == "completed"


# ============================ 6. Timeout / cancellation ===================================

def test_timeout_path_returns_minus_one_not_minus_nine(monkeypatch) -> None:
    """The distinction the diagnosis rested on: the runner's OWN timeout is -1. A -9 therefore
    proves an EXTERNAL kill, which is what pointed at the cgroup OOM killer."""
    class _SlowStream:
        """Yields one chunk, then blocks past the deadline instead of signalling EOF.

        run_with_timeout waits on the stream PUMPS, not on proc.wait() -- a stream that hits
        EOF immediately makes the run look successful no matter what wait() does.
        """

        def __init__(self, first: bytes):
            self._first: bytes | None = first

        async def read(self, _n: int = -1) -> bytes:
            if self._first is not None:
                chunk, self._first = self._first, None
                return chunk
            await asyncio.sleep(10)
            return b""

    class _Timed:
        """Never exits on its own. Needs terminate()/kill()/wait() because the timeout path
        goes through base.terminate_and_reap()."""

        def __init__(self):
            self.stdout = _SlowStream(b"https://target.example/a\n")
            self.stderr = _SlowStream(b"")
            self.stdin = _FakeStdin()
            self.returncode = None

        async def wait(self):
            if self.returncode is not None:
                return self.returncode
            await asyncio.sleep(10)
            return 0

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*_command, **_kwargs):
        return _Timed()

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://target.example", {"timeout_seconds": 0.2}, []))

    assert raw.exit_code == -1
    assert "timed out" in raw.stderr
    assert "https://target.example/a" in raw.stdout      # partial output preserved


def test_timeout_budget_scales_and_is_overridable() -> None:
    """The budget must stay derived from work, not flattened to a global constant."""
    one = katana_runner.compute_timeout(1, 2, js_crawl=True)
    many = katana_runner.compute_timeout(5, 2, js_crawl=True)
    deeper = katana_runner.compute_timeout(1, 4, js_crawl=True)
    assert many > one
    assert deeper > one
    assert katana_runner.MIN_TIMEOUT_SECONDS <= one <= katana_runner.MAX_TIMEOUT_SECONDS


# ============================ 7. Metadata =================================================

def test_declared_version_matches_the_installed_binary() -> None:
    """Reported as tool metadata on findings; drifted to 1.1.2 while the image shipped 1.7.0."""
    assert katana_runner.KatanaRunner().version == "1.7.0"


def test_capability_and_binary_are_unchanged() -> None:
    """Guards the task boundary: katana is not removed, replaced, or re-pointed."""
    runner = katana_runner.KatanaRunner()
    assert runner.name == "katana"
    assert runner.binary == "katana"
    assert runner.capability == "web_crawling"


# ============================ 8. Per-target process isolation =============================
#
# THE memory fix. One katana process per target, because katana's dedup state
# (filters.Simple: UniqueURL + UniqueContent, plus common.Shared/DomainCounter) is built once
# per process and released only by Close() at process exit -- the installed v1.7.0 binary
# exposes no Reset/Clear/Purge for it. Feeding N targets to one process therefore grows the
# live set with CUMULATIVE crawl volume, which GOMEMLIMIT cannot reclaim because it is still
# reachable. Measured: 29- and 44-target single-process runs were OOM-killed at a 4096 MiB cap
# while every 1-target run survived, including one that crawled 109,214 URLs.

def _targets(*urls: str):
    """prior_findings that make web_targets() return exactly `urls`, in order."""
    return [CommonFinding(asset_type="http_service", value=u, metadata={}) for u in urls]


class _Recorder:
    """Captures every subprocess launch so per-process isolation can be asserted."""

    def __init__(self, outcomes=None):
        # outcomes: (stdout_chunks, returncode) per launch; the last entry repeats.
        self.outcomes = list(outcomes or [([b"https://a.example/1\n"], 0)])
        self.launches: list[dict] = []

    def install(self, monkeypatch):
        async def _fake_exec(*command, **kwargs):
            idx = len(self.launches)
            stdout, rc = self.outcomes[min(idx, len(self.outcomes) - 1)]
            proc = _FakeProc(stdout=list(stdout), stderr=(), returncode=rc)
            self.launches.append({"command": list(command), "proc": proc,
                                  "env": kwargs.get("env")})
            return proc

        monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
        return self

    @property
    def stdins(self) -> list[str]:
        return [launch["proc"].stdin.written.decode() for launch in self.launches]


def _run_multi(monkeypatch, urls, outcomes=None, config=None):
    rec = _Recorder(outcomes).install(monkeypatch)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://target.example", config or {}, _targets(*urls)))
    return raw, rec


# --- one process per target ---------------------------------------------------------------

def test_each_target_gets_its_own_process(monkeypatch) -> None:
    """THE fix: N targets => N processes, never one shared process."""
    urls = [f"https://h{i}.example" for i in range(5)]
    _raw, rec = _run_multi(monkeypatch, urls)
    assert len(rec.launches) == 5


def test_multiple_targets_are_never_sent_to_one_process(monkeypatch) -> None:
    """REGRESSION GUARD. Fails the moment multi-target-single-process behaviour returns --
    the exact shape that was OOM-killed at 29 and 44 targets."""
    urls = [f"https://h{i}.example" for i in range(6)]
    _raw, rec = _run_multi(monkeypatch, urls)
    for written in rec.stdins:
        assert len([p for p in written.split("\n") if p.strip()]) == 1, (
            f"more than one target on one stdin: {written!r}"
        )


def test_stdin_never_contains_more_than_one_url(monkeypatch) -> None:
    urls = ["https://a.example", "https://b.example", "https://c.example"]
    _raw, rec = _run_multi(monkeypatch, urls)
    assert [s.strip() for s in rec.stdins] == urls


def test_each_process_receives_exactly_one_target_in_order(monkeypatch) -> None:
    urls = ["https://one.example", "https://two.example"]
    _raw, rec = _run_multi(monkeypatch, urls)
    assert rec.stdins[0].strip() == "https://one.example"
    assert rec.stdins[1].strip() == "https://two.example"
    assert all(launch["proc"].stdin.closed for launch in rec.launches)


def test_targets_never_leak_into_argv(monkeypatch) -> None:
    """Scope stays controlled by stdin + -field-scope, never by argv."""
    urls = ["https://a.example", "https://b.example"]
    _raw, rec = _run_multi(monkeypatch, urls)
    for launch in rec.launches:
        for url in urls:
            assert url not in launch["command"]


def test_processes_run_sequentially_not_concurrently(monkeypatch) -> None:
    """Targets are crawled one at a time: the previous process must be finished before the
    next starts, otherwise two crawls' state is resident at once -- the thing being fixed."""
    order: list[str] = []
    launches = {"n": 0}

    class _Seq(_FakeProc):
        def __init__(self, tag):
            super().__init__(stdout=[b"https://x.example/1\n"], returncode=0)
            self.tag = tag

        async def wait(self):
            order.append("end:" + self.tag)
            return await super().wait()

    async def _fake_exec(*_command, **_kwargs):
        launches["n"] += 1
        tag = str(launches["n"])
        order.append("start:" + tag)
        return _Seq(tag)

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    asyncio.run(runner.run("https://t.example", {}, _targets(
        "https://a.example", "https://b.example", "https://c.example")))

    assert order == ["start:1", "end:1", "start:2", "end:2", "start:3", "end:3"]


# --- output concatenation -----------------------------------------------------------------

def test_stdout_is_concatenated_in_target_order(monkeypatch) -> None:
    raw, _rec = _run_multi(
        monkeypatch,
        ["https://a.example", "https://b.example"],
        outcomes=[([b"https://a.example/1\n"], 0), ([b"https://b.example/1\n"], 0)],
    )
    assert raw.stdout.splitlines() == ["https://a.example/1", "https://b.example/1"]


def test_missing_trailing_newline_does_not_merge_two_urls(monkeypatch) -> None:
    """A process killed mid-write can leave a chunk without its newline; naive concatenation
    would glue its last URL to the next target's first and corrupt BOTH."""
    raw, _rec = _run_multi(
        monkeypatch,
        ["https://a.example", "https://b.example"],
        outcomes=[([b"https://a.example/1"], -9), ([b"https://b.example/1\n"], 0)],
    )
    assert "https://a.example/1https://b.example/1" not in raw.stdout
    assert raw.stdout.splitlines() == ["https://a.example/1", "https://b.example/1"]


def test_parser_input_is_unchanged_for_a_single_target(monkeypatch) -> None:
    """Backward compatibility: one target must still produce exactly the old parser input."""
    raw, rec = _run_multi(
        monkeypatch, ["https://solo.example"],
        outcomes=[([b"https://solo.example/a\nhttps://solo.example/b\n"], 0)],
    )
    assert len(rec.launches) == 1
    assert raw.stdout == "https://solo.example/a\nhttps://solo.example/b\n"
    assert raw.exit_code == 0


def test_parse_is_unchanged_and_dedupes_across_targets(monkeypatch) -> None:
    """parse() itself is untouched; its existing `seen` set absorbs cross-process duplicates."""
    raw, _rec = _run_multi(
        monkeypatch,
        ["https://a.example", "https://b.example"],
        outcomes=[([b"https://dup.example/x\n"], 0), ([b"https://dup.example/x\n"], 0)],
    )
    findings = katana_runner.KatanaRunner().parse(raw)
    assert [f.value for f in findings] == ["https://dup.example/x"]


# --- timeout accounting -------------------------------------------------------------------

def test_per_target_timeout_is_derived_from_crawl_duration() -> None:
    """Not a magic 480: it is crawl-duration x the documented safety factor."""
    expected = int(katana_runner.CRAWL_DURATION_SECONDS * katana_runner.PER_TARGET_SAFETY_FACTOR)
    assert katana_runner.compute_per_target_timeout() == expected
    assert katana_runner.compute_per_target_timeout(300) == 480


def test_per_target_timeout_tracks_a_configured_crawl_duration() -> None:
    assert katana_runner.compute_per_target_timeout(600) == 960


def test_per_target_timeout_exceeds_crawl_duration() -> None:
    """katana must be able to stop itself at -crawl-duration and exit 0 BEFORE the runner's
    own deadline fires, otherwise every run degrades to exit -1."""
    assert katana_runner.compute_per_target_timeout(300) > 300


def test_per_target_timeout_is_independent_of_target_count() -> None:
    """The whole point of the split: a long list must not squeeze each target's deadline."""
    one = katana_runner.compute_per_target_timeout(300)
    assert katana_runner.compute_total_budget(1, one) == one
    assert katana_runner.compute_total_budget(44, one) == 44 * one


def test_total_budget_is_derived_from_count_not_a_fixed_ceiling() -> None:
    """A fixed 3600s cap would cover only ~7 of 44 targets and silently drop the other 37."""
    budget = katana_runner.compute_total_budget(44, katana_runner.compute_per_target_timeout(300))
    assert budget == 44 * 480
    assert budget > katana_runner.MAX_TIMEOUT_SECONDS


def test_per_target_floor_survives_a_tiny_configured_duration() -> None:
    assert katana_runner.compute_per_target_timeout(1) == katana_runner.MIN_PER_TARGET_SECONDS


def test_budget_exhaustion_names_unprocessed_targets(monkeypatch) -> None:
    """Running out of budget must be VISIBLE, never a silent truncation.

    The first target is always attempted (an unrealistically small configured total must not
    produce a run that crawled nothing); the targets behind it are reported by name."""
    urls = [f"https://h{i}.example" for i in range(4)]
    rec = _Recorder([([b"https://x.example/1\n"], 0)]).install(monkeypatch)

    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://t.example", {"timeout_seconds": 1}, _targets(*urls)))

    assert len(rec.launches) == 1                  # best effort, not zero
    assert "3 target(s) not attempted" in raw.stderr
    for url in urls[1:]:
        assert url in raw.stderr


def test_first_target_is_always_attempted_however_small_the_budget(monkeypatch) -> None:
    """Guards the fix above: a tiny explicit timeout must still crawl something."""
    rec = _Recorder([([b"https://x.example/1\n"], 0)]).install(monkeypatch)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run(
        "https://t.example", {"timeout_seconds": 1},
        _targets("https://a.example", "https://b.example"),
    ))
    assert len(rec.launches) == 1
    assert "https://x.example/1" in raw.stdout


# --- partial failure handling -------------------------------------------------------------

def test_one_target_sigkill_does_not_stop_the_rest(monkeypatch) -> None:
    """A per-target OOM kill now costs ONE target, not the entire crawl."""
    raw, rec = _run_multi(
        monkeypatch,
        ["https://a.example", "https://b.example", "https://c.example"],
        outcomes=[([b"https://a.example/1\n"], -9),
                  ([b"https://b.example/1\n"], 0),
                  ([b"https://c.example/1\n"], 0)],
    )
    assert len(rec.launches) == 3
    assert "https://b.example/1" in raw.stdout
    assert "https://c.example/1" in raw.stdout


def test_sigkill_on_one_target_is_diagnosed_in_the_summary(monkeypatch) -> None:
    raw, _rec = _run_multi(
        monkeypatch, ["https://a.example", "https://b.example"],
        outcomes=[([b"https://a.example/1\n"], -9), ([b"https://b.example/1\n"], 0)],
    )
    assert "exit=-9" in raw.stderr
    assert "SIGKILL" in raw.stderr
    assert "OOM" in raw.stderr
    assert "1 killed" in raw.stderr


def test_nonzero_exit_on_one_target_does_not_stop_the_rest(monkeypatch) -> None:
    raw, rec = _run_multi(
        monkeypatch, ["https://a.example", "https://b.example"],
        outcomes=[([b""], 3), ([b"https://b.example/1\n"], 0)],
    )
    assert len(rec.launches) == 2
    assert "https://b.example/1" in raw.stdout


def test_partial_timeout_continues_to_the_next_target(monkeypatch) -> None:
    """A slow host must not cost every target behind it in the list."""
    launches = {"n": 0}

    class _SlowStream:
        def __init__(self, first: bytes):
            self._first: bytes | None = first

        async def read(self, _n: int = -1) -> bytes:
            if self._first is not None:
                chunk, self._first = self._first, None
                return chunk
            await asyncio.sleep(10)
            return b""

    class _Hang:
        def __init__(self):
            self.stdout = _SlowStream(b"https://slow.example/1\n")
            self.stderr = _SlowStream(b"")
            self.stdin = _FakeStdin()
            self.returncode = None

        async def wait(self):
            if self.returncode is not None:
                return self.returncode
            await asyncio.sleep(10)
            return 0

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*_command, **_kwargs):
        launches["n"] += 1
        if launches["n"] == 1:
            return _Hang()
        return _FakeProc(stdout=[b"https://fast.example/1\n"], returncode=0)

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(katana_runner, "compute_per_target_timeout", lambda *_a, **_k: 1)

    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://t.example", {"timeout_seconds": 600}, _targets(
        "https://slow.example", "https://fast.example")))

    assert launches["n"] == 2                          # the second target still ran
    assert "https://slow.example/1" in raw.stdout      # partial output preserved
    assert "https://fast.example/1" in raw.stdout
    assert "timed out" in raw.stderr


# --- aggregate classification -------------------------------------------------------------

def test_aggregate_exit_is_zero_only_when_all_targets_succeed(monkeypatch) -> None:
    raw, _rec = _run_multi(
        monkeypatch, ["https://a.example", "https://b.example"],
        outcomes=[([b"https://a.example/1\n"], 0), ([b"https://b.example/1\n"], 0)],
    )
    assert raw.exit_code == 0
    assert classify_run(katana_runner.KatanaRunner(), raw, True) == "completed"


def test_mixed_results_classify_partial_not_failed(monkeypatch) -> None:
    """One target failing must NOT fail the whole scan while usable output exists."""
    raw, _rec = _run_multi(
        monkeypatch, ["https://a.example", "https://b.example"],
        outcomes=[([b"https://a.example/1\n"], -9), ([b"https://b.example/1\n"], 0)],
    )
    assert raw.exit_code == -1
    assert classify_run(katana_runner.KatanaRunner(), raw, True) == "partial"


def test_all_targets_failing_with_no_output_classifies_failed(monkeypatch) -> None:
    """Existing failure semantics preserved: nothing usable anywhere => failed."""
    raw, _rec = _run_multi(
        monkeypatch, ["https://a.example", "https://b.example"],
        outcomes=[([b""], -9), ([b""], -9)],
    )
    assert raw.exit_code == -1
    assert classify_run(katana_runner.KatanaRunner(), raw, False) == "failed"


# --- no loss of targets -------------------------------------------------------------------

def test_all_targets_are_attempted(monkeypatch) -> None:
    """No target cap, no batching, no sampling: every target gets a process."""
    urls = [f"https://h{i}.example" for i in range(44)]
    _raw, rec = _run_multi(monkeypatch, urls)
    assert len(rec.launches) == 44
    assert sorted(s.strip() for s in rec.stdins) == sorted(urls)


def test_summary_accounts_for_every_target(monkeypatch) -> None:
    urls = [f"https://h{i}.example" for i in range(4)]
    raw, _rec = _run_multi(monkeypatch, urls)
    assert f"{len(urls)} target(s)" in raw.stderr
    for url in urls:
        assert url in raw.stderr


# --- capability preservation --------------------------------------------------------------

def test_js_crawl_present_in_every_invocation(monkeypatch) -> None:
    """The capability this fix must not trade away, asserted per PROCESS.

    -js-crawl is the one that carries the coverage (measured 2580 URLs at a 72 MiB peak) and
    stays unconditional. -jsluice is opt-in and therefore absent by default."""
    _raw, rec = _run_multi(monkeypatch, [f"https://h{i}.example" for i in range(4)])
    for launch in rec.launches:
        assert "-js-crawl" in launch["command"]
        assert "-jsluice" not in launch["command"]


def test_jsluice_is_opt_in_and_applies_to_every_process(monkeypatch) -> None:
    """Enabling it explicitly puts it on EVERY per-target process, not just the first."""
    _raw, rec = _run_multi(
        monkeypatch, [f"https://h{i}.example" for i in range(4)], config={"jsluice": True},
    )
    assert len(rec.launches) == 4
    for launch in rec.launches:
        assert "-jsluice" in launch["command"]
        assert "-js-crawl" in launch["command"]


def test_parallelism_two_present_in_every_invocation(monkeypatch) -> None:
    _raw, rec = _run_multi(monkeypatch, [f"https://h{i}.example" for i in range(4)])
    for launch in rec.launches:
        cmd = launch["command"]
        assert cmd[cmd.index("-parallelism") + 1] == "2"


def test_all_required_flags_present_in_every_invocation(monkeypatch) -> None:
    """Every process is the FULL katana invocation -- no reduced variant for later targets."""
    expected = {
        "-depth": "2", "-field-scope": "fqdn", "-concurrency": "3", "-parallelism": "2",
        "-rate-limit": "150", "-timeout": "10", "-max-response-size": "1048576",
        "-max-domain-pages": "2000", "-crawl-duration": "300s",
    }
    _raw, rec = _run_multi(monkeypatch, ["https://a.example", "https://b.example"])
    for launch in rec.launches:
        cmd = launch["command"]
        for flag, value in expected.items():
            assert cmd[cmd.index(flag) + 1] == value
        assert "-js-crawl" in cmd
        assert "-jsluice" not in cmd  # opt-in; see JSLUICE_DEFAULT


def test_gomemlimit_env_is_passed_to_every_process(monkeypatch) -> None:
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: 4 * 1024**3)
    _raw, rec = _run_multi(monkeypatch, ["https://a.example", "https://b.example"])
    for launch in rec.launches:
        assert launch["env"]["GOMEMLIMIT"] == "1433MiB"


# ============================ 9. Duplicate bare-host targets ===============================
#
# THE duplicate-execution fix. `web_targets()` -> `http_service_urls()` now collapses
# `https://host` and `https://host/` before katana ever sees them (see _web.py's
# `_dedupe_bare_hosts()`). Evidence: a real 29-target run had `new`, `www`, the root domain,
# `cpanel` and `webmail` each crawled TWICE this way, and every one of those pairs was
# already at the per-target timeout/OOM boundary -- duplication doubled cost on exactly the
# targets that could least afford it, for zero additional coverage (both strings are the
# same resource). This is a target-SELECTION fix upstream of KatanaRunner.run(); the runner
# itself is unchanged, so it is verified here as an end-to-end launch-count guard.

def test_bare_host_and_trailing_slash_launch_katana_exactly_once(monkeypatch) -> None:
    """THE regression this fix closes: one logical host, one katana process."""
    findings = [
        CommonFinding(asset_type="http_service", value="https://host.example", metadata={}),
        CommonFinding(asset_type="http_service", value="https://host.example/", metadata={}),
    ]
    rec = _Recorder([([b"https://host.example/a\n"], 0)]).install(monkeypatch)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://host.example", {}, findings))

    assert len(rec.launches) == 1
    assert rec.stdins[0].strip() == "https://host.example"
    assert "1 target(s)" in raw.stderr


def test_distinct_hosts_still_each_get_their_own_process(monkeypatch) -> None:
    """The fix narrows only the bare-host+slash pair; genuinely different hosts are untouched."""
    findings = [
        CommonFinding(asset_type="http_service", value="https://a.example", metadata={}),
        CommonFinding(asset_type="http_service", value="https://a.example/", metadata={}),
        CommonFinding(asset_type="http_service", value="https://b.example", metadata={}),
    ]
    rec = _Recorder([([b"x\n"], 0)]).install(monkeypatch)
    runner = katana_runner.KatanaRunner()
    asyncio.run(runner.run("https://a.example", {}, findings))

    assert len(rec.launches) == 2
    assert [s.strip() for s in rec.stdins] == ["https://a.example", "https://b.example"]


# ============ Per-target OUTPUT budget (resource-limited execution) =========================
#
# These cover the resource path that per-target PROCESS isolation did NOT: a single target
# emitting so much output that the PARENT's accumulation exhausts the worker cgroup. The
# fixtures below are synthetic high-volume generators -- deliberately NOT the real 163k-URL
# target, which must not be re-crawled merely to exercise a bound.


class _FloodStream:
    """A stdout pipe that keeps emitting URLs, the way a pathological crawl does.

    `max_chunks` exists only so a BROKEN implementation fails the test instead of hanging the
    suite forever; a correct one stops reading long before reaching it.
    """

    def __init__(self, line: bytes = b"https://flood.example/" + b"p" * 40 + b"\n",
                 per_chunk: int = 200, max_chunks: int = 10_000):
        self.line = line
        self.per_chunk = per_chunk
        self.max_chunks = max_chunks
        self.chunks_served = 0

    async def read(self, _n: int = -1) -> bytes:
        if self.chunks_served >= self.max_chunks:
            return b""
        self.chunks_served += 1
        return self.line * self.per_chunk


class _FloodProc:
    """A subprocess that floods stdout and never exits on its own."""

    def __init__(self, stream=None):
        self.stdout = stream or _FloodStream()
        self.stderr = _FakeStream([])
        self.stdin = _FakeStdin()
        self.returncode = None
        self.killed = 0
        self.reaped = False

    async def wait(self):
        if self.returncode is None:
            self.returncode = -9
        return self.returncode

    def kill(self):
        self.killed += 1
        self.returncode = -9

    async def communicate(self):
        self.reaped = True
        return b"", b""


def _run_flood(monkeypatch, *, targets=1, config=None):
    """Drive the runner against `targets` flooding processes."""
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        proc = _FloodProc()
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    prior = _targets(*[f"https://h{i}.example" for i in range(targets)]) if targets > 1 else []
    raw = asyncio.run(runner.run("https://target.example", config or {}, prior))
    return raw, procs


# --- 1. the budget exists and is enforced --------------------------------------------------

def test_both_budgets_are_independent_not_derived_from_each_other() -> None:
    """The URL budget is NO LONGER multiplied into the byte budget.

    That derivation was the bug: `max_urls_per_target=10000` produced a 5,120,000-byte cap
    and NO URL enforcement, so a run configured for 10,000 URLs was observed stopping at
    74,364. Both numbers are now real and separately configurable."""
    urls, byts = katana_runner.resolve_output_budgets({})
    assert urls == katana_runner.MAX_URLS_PER_TARGET == 10_000
    assert byts == katana_runner.MAX_STDOUT_BYTES_PER_TARGET == 5 * 1024 * 1024
    # Changing one must not move the other.
    urls2, byts2 = katana_runner.resolve_output_budgets({"max_urls_per_target": 25})
    assert (urls2, byts2) == (25, katana_runner.MAX_STDOUT_BYTES_PER_TARGET)
    urls3, byts3 = katana_runner.resolve_output_budgets({"max_stdout_bytes_per_target": 4096})
    assert (urls3, byts3) == (katana_runner.MAX_URLS_PER_TARGET, 4096)


def test_the_5mib_byte_boundary_is_preserved() -> None:
    """The memory boundary the runtime validation exercised must not move."""
    assert katana_runner.MAX_STDOUT_BYTES_PER_TARGET == 5_242_880


def test_a_pathological_target_is_bounded_not_unbounded(monkeypatch) -> None:
    """THE fix. A target that would emit unbounded output is stopped at its budget."""
    # A tiny BYTE budget, so this test exercises the byte boundary specifically.
    cap = 4096
    raw, procs = _run_flood(monkeypatch, config={"max_stdout_bytes_per_target": cap})
    # The cap is PER PROCESS, and web_targets() expands a bare target into its http:// and
    # https:// forms -- so the aggregate bound is cap x len(procs), not cap. What matters is
    # that it is a BOUND at all: without the fix this is the whole flood.
    #
    # The "+ 1 per process" is the runner's newline repair: truncating mid-line leaves a chunk
    # without its trailing newline, and the runner appends one so the last URL of one target
    # cannot be glued to the first URL of the next. One byte each, and load-bearing.
    assert len(raw.stdout.encode()) <= (cap + 1) * len(procs)
    # Each process was OFFERED far more than its budget and still stayed within it.
    for proc in procs:
        offered = proc.stdout.chunks_served * proc.stdout.per_chunk * len(proc.stdout.line)
        assert offered > cap, "the fixture did not actually exceed the budget"
    # And it did not simply read the generator dry.
    for proc in procs:
        assert proc.stdout.chunks_served < proc.stdout.max_chunks


# --- 2. invalid budget rejected BEFORE any process spawns ----------------------------------

def test_zero_budget_is_rejected_not_treated_as_unlimited() -> None:
    with pytest.raises(katana_runner.KatanaBudgetError):
        katana_runner.resolve_output_budgets({"max_urls_per_target": 0})


def test_negative_budget_is_rejected() -> None:
    with pytest.raises(katana_runner.KatanaBudgetError):
        katana_runner.resolve_output_budgets({"max_urls_per_target": -1})


def test_an_invalid_byte_budget_is_rejected_too() -> None:
    """BOTH budgets are safety controls, so both are validated."""
    with pytest.raises(katana_runner.KatanaBudgetError):
        katana_runner.resolve_output_budgets({"max_stdout_bytes_per_target": 0})


def test_invalid_budget_rejected_before_any_process_is_spawned(monkeypatch) -> None:
    """The guard must fire ahead of the loop, not after spawning N-1 processes."""
    spawned: list = []

    async def _fake_exec(*command, **kwargs):
        spawned.append(command)
        return _FakeProc(stdout=[b""], returncode=0)

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    with pytest.raises(katana_runner.KatanaBudgetError):
        asyncio.run(runner.run("https://target.example", {"max_urls_per_target": 0},
                               _targets("https://a.example", "https://b.example")))
    assert spawned == []


# --- 3./4. the run becomes resource-limited AND keeps what it collected --------------------

def test_flooding_target_is_marked_resource_limited(monkeypatch) -> None:
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert "exit=resource_limited" in raw.stderr


def test_output_collected_before_termination_is_preserved(monkeypatch) -> None:
    """Bounded is not the same as discarded: the prefix survives."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    lines = [ln for ln in raw.stdout.splitlines() if ln.strip()]
    assert lines, "collected output was discarded instead of preserved"
    assert all(ln.startswith("https://flood.example/") for ln in lines)


def test_truncation_at_the_budget_does_not_splice_two_targets_urls(monkeypatch) -> None:
    """A cap that lands mid-line must not glue one target's last URL to the next's first.

    The budget makes mid-line truncation ROUTINE rather than exceptional (it stops reading at
    an arbitrary byte offset), so the runner's newline repair is now load-bearing on the
    common path, not just after a SIGKILL."""
    raw, procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert len(procs) > 1, "this test needs more than one process to be meaningful"
    for line in raw.stdout.splitlines():
        if line.strip():
            # A spliced line would contain a second scheme partway through.
            assert line.strip().count("https://") == 1


def test_preserved_output_still_parses_into_findings(monkeypatch) -> None:
    """Preservation is only meaningful if the URLs remain usable downstream."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    findings = katana_runner.KatanaRunner().parse(raw)
    assert findings
    assert all(f.asset_type == "url" for f in findings)


# --- 5. the process is terminated and reaped ----------------------------------------------

def test_resource_limited_process_is_terminated_and_reaped(monkeypatch) -> None:
    _raw, procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert procs[0].killed >= 1, "the flooding process was not terminated"
    assert procs[0].reaped, "the flooding process was not reaped"
    assert procs[0].returncode is not None


# --- 6./7./8. outcomes stay DISTINCT -------------------------------------------------------

def test_resource_limit_is_distinct_from_timeout(monkeypatch) -> None:
    """A budget kill must not masquerade as a timeout, or an operator raises the wrong knob."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert raw.timed_out is False
    assert "timed out" not in raw.stderr


def test_timeout_path_does_not_claim_resource_limited(monkeypatch) -> None:
    """The existing timeout path is unchanged and does NOT claim resource_limited."""
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    assert raw.timed_out is False
    # NB: the header always carries a "(N resource_limited)" tally, so a bare substring test
    # would be vacuous. Key on the per-target marker, and assert the tally is zero.
    assert "exit=resource_limited" not in raw.stderr
    assert "(0 resource_limited)" in raw.stderr


def test_process_failure_remains_distinct(monkeypatch) -> None:
    """A plain non-zero exit is neither a timeout nor a resource limit."""
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=2)
    assert "exit=2" in raw.stderr
    assert "exit=resource_limited" not in raw.stderr
    assert "(0 resource_limited)" in raw.stderr
    assert raw.timed_out is False


def test_sigkill_remains_distinct_from_resource_limit(monkeypatch) -> None:
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=-9)
    assert "exit=-9" in raw.stderr
    assert "exit=resource_limited" not in raw.stderr
    assert "(0 resource_limited)" in raw.stderr


def test_resource_limited_run_can_never_be_successful(monkeypatch) -> None:
    """THE correctness rule: a capped crawl is partial, never `completed`."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert raw.exit_code != 0
    assert classify_run(katana_runner.KatanaRunner(), raw, produced_findings=True) == "partial"


def test_resource_limited_summary_does_not_claim_completion(monkeypatch) -> None:
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert "0 completed" in raw.stderr


def test_resource_limited_summary_warns_surface_is_not_proven_absent(monkeypatch) -> None:
    """A partial crawl must never read as evidence the rest of the surface does not exist."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert "NOT proven absent" in raw.stderr


# --- 9./10. isolation holds: one bad target does not harm the others -----------------------

def test_one_flooding_target_does_not_terminate_the_others(monkeypatch) -> None:
    """Only the offending process is killed; the rest run and are not touched."""
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        # First target floods; the rest behave.
        if not procs:
            proc = _FloodProc()
        else:
            proc = _FakeProc(stdout=[b"https://ok.example/1\n"], returncode=0)
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run(
        "https://target.example", {"max_urls_per_target": 100},
        _targets("https://a.example", "https://b.example", "https://c.example"),
    ))
    assert len(procs) == 3, "a flooding target stopped the others from being attempted"
    assert procs[0].killed >= 1
    # The healthy processes exited on their own terms and were never killed.
    assert procs[1].returncode == 0 and procs[2].returncode == 0
    assert "https://ok.example/1" in raw.stdout


def test_flooding_target_does_not_consume_another_targets_budget(monkeypatch) -> None:
    """The budget is PER PROCESS, so a healthy later target still gets its full output."""
    calls = {"n": 0}

    async def _fake_exec(*command, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FloodProc()
        return _FakeProc(stdout=[b"https://ok.example/kept\n"], returncode=0)

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run(
        "https://target.example", {"max_urls_per_target": 100},
        _targets("https://a.example", "https://b.example"),
    ))
    assert "https://ok.example/kept" in raw.stdout


def test_process_per_target_isolation_is_intact_under_a_budget(monkeypatch) -> None:
    """The existing isolation property must survive the new control."""
    urls = [f"https://h{i}.example" for i in range(4)]
    _raw, rec = _run_multi(monkeypatch, urls, config={"max_urls_per_target": 100})
    assert len(rec.launches) == 4
    for stdin in rec.stdins:
        assert len(stdin.split()) == 1  # exactly one target per process


# --- 11. reproducibility --------------------------------------------------------------------

def test_effective_limits_are_recorded_for_reproducibility(monkeypatch) -> None:
    """The command string is hashed into ToolRun.command_hash / effective_command."""
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    for key in ("katana_version=", "per_target_timeout_s=", "crawl_duration_s=",
                "crawl_depth=", "max_urls_per_target=", "max_stdout_bytes_per_target=",
                "parallelism=", "concurrency=", "gomemlimit_mib="):
        assert key in raw.command, f"{key} missing from the reproducibility record"


def test_reproducibility_records_the_configured_budget_not_the_default(monkeypatch) -> None:
    raw, _captured = _run_katana(
        monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0,
        config={"max_urls_per_target": 250},
    )
    assert "max_urls_per_target=250" in raw.command
    # The byte budget is INDEPENDENT -- it stays at its default when only URLs are configured.
    assert f"max_stdout_bytes_per_target={katana_runner.MAX_STDOUT_BYTES_PER_TARGET}" in raw.command


def test_unavailable_gomemlimit_is_reported_not_invented(monkeypatch) -> None:
    """No cgroup limit => say so, never substitute a plausible number."""
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: None)
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    assert "gomemlimit_mib=unavailable" in raw.command


def test_declared_katana_version_is_recorded(monkeypatch) -> None:
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    assert f"katana_version={katana_runner.KatanaRunner.version}" in raw.command


# --- 12./13. nothing else changed ------------------------------------------------------------

def test_normal_output_parsing_is_unchanged_under_the_budget(monkeypatch) -> None:
    """A normal run is identical in what it parses."""
    out = b"https://a.example/1\nhttps://a.example/2?q=1\n"
    raw, _captured = _run_katana(monkeypatch, stdout=[out], returncode=0)
    findings = katana_runner.KatanaRunner().parse(raw)
    assert [f.value for f in findings] == ["https://a.example/1", "https://a.example/2?q=1"]
    assert findings[1].metadata["has_params"] is True


def test_a_normal_run_is_not_marked_resource_limited(monkeypatch) -> None:
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    assert raw.exit_code == 0
    assert "exit=resource_limited" not in raw.stderr
    assert "(0 resource_limited)" in raw.stderr
    assert classify_run(katana_runner.KatanaRunner(), raw, produced_findings=True) == "completed"


def test_scope_filtering_is_unchanged(monkeypatch) -> None:
    """-field-scope fqdn still pins the crawl to the target host."""
    _raw, captured = _run_katana(monkeypatch, stdout=[b""], returncode=0)
    cmd = captured["command"]
    assert "-field-scope" in cmd
    assert cmd[cmd.index("-field-scope") + 1] == "fqdn"


def test_budget_does_not_alter_the_crawl_flags(monkeypatch) -> None:
    """The bound is on OUTPUT, not on coverage: js-crawl/depth are untouched."""
    _raw, captured = _run_katana(monkeypatch, stdout=[b""], returncode=0,
                                 config={"max_urls_per_target": 100})
    cmd = captured["command"]
    assert "-js-crawl" in cmd
    assert cmd[cmd.index("-depth") + 1] == "2"


# --- 14. a partial crawl creates no finding/verification status -----------------------------

def test_partial_crawl_creates_no_finding_merely_because_it_was_capped(monkeypatch) -> None:
    """A resource limit is an EXECUTION fact, never a vulnerability signal."""
    raw, _procs = _run_flood(monkeypatch, config={"max_urls_per_target": 100})
    findings = katana_runner.KatanaRunner().parse(raw)
    # Only crawled URLs -- no synthetic "crawl was truncated" finding.
    assert all(f.asset_type == "url" for f in findings)
    assert all(f.metadata.get("source") == "katana" for f in findings)
    assert not any("resource" in f.value.lower() or "limit" in f.value.lower()
                   for f in findings)


# ============ URL-count budget is GENUINELY enforced =======================================
#
# The semantics bug these cover: `max_urls_per_target` used to be multiplied by 512 into a
# byte cap and never enforced as a count, so a run configured for 10,000 URLs stopped at
# 74,364. Both limits are now real, and whichever is hit FIRST wins.

class _ShortLineFloodStream(_FloodStream):
    """Floods SHORT URLs, so the URL cap is reached long before any sane byte cap.

    This is the exact shape that exposed the old bug: real URLs are far shorter than the
    512-byte estimate, so the byte cap always fired first and the URL count never bound.
    """

    def __init__(self, per_chunk: int = 200, max_chunks: int = 10_000):
        super().__init__(line=b"https://s.test/a\n", per_chunk=per_chunk, max_chunks=max_chunks)


def _run_short_flood(monkeypatch, *, config=None):
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        proc = _FloodProc(_ShortLineFloodStream())
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    runner = katana_runner.KatanaRunner()
    raw = asyncio.run(runner.run("https://target.example", config or {}, []))
    return raw, procs


def test_url_budget_is_actually_enforced_as_a_count(monkeypatch) -> None:
    """THE fix. A 100-URL budget stops at 100 URLs per process -- not at a byte estimate."""
    raw, procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    total = len([ln for ln in raw.stdout.splitlines() if ln.strip()])
    # Each process contributes at most its budget; nothing exceeds count x processes.
    assert total <= 100 * len(procs)
    # And it genuinely reached the cap rather than stopping early for some other reason.
    assert total == 100 * len(procs)


def test_short_urls_no_longer_overshoot_the_configured_count(monkeypatch) -> None:
    """The regression guard for the reported bug.

    With the old derivation, 100 URLs became a 51,200-byte cap and ~3,000 short URLs got
    through. The count must now bind regardless of how short the URLs are."""
    raw, procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    total = len([ln for ln in raw.stdout.splitlines() if ln.strip()])
    assert total < 500, f"URL cap did not bind: {total} URLs for a 100-URL budget"


def test_url_limited_run_reports_the_url_limit_not_the_byte_limit(monkeypatch) -> None:
    """An operator must be told WHICH limit fired, so they raise the right one."""
    raw, _procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert "URL limit (100 URL(s))" in raw.stderr
    assert "output byte limit" not in raw.stderr


def test_byte_limited_run_reports_the_byte_limit(monkeypatch) -> None:
    """The other side of the same contract: a byte-bound run says so."""
    raw, _procs = _run_flood(monkeypatch, config={"max_stdout_bytes_per_target": 4096})
    assert "output byte limit (4096 bytes)" in raw.stderr
    assert "URL limit" not in raw.stderr


def test_whichever_limit_comes_first_wins(monkeypatch) -> None:
    """Long URLs hit BYTES first; short URLs hit the COUNT first. Same config, both paths."""
    # Long lines (~63 bytes each): a 10,000-byte cap is reached well before 10,000 URLs.
    long_raw, _ = _run_flood(
        monkeypatch, config={"max_urls_per_target": 10_000, "max_stdout_bytes_per_target": 10_000})
    assert "output byte limit" in long_raw.stderr
    # Short lines with a generous byte cap: the URL count binds instead.
    short_raw, _ = _run_short_flood(
        monkeypatch, config={"max_urls_per_target": 50, "max_stdout_bytes_per_target": 5_000_000})
    assert "URL limit (50 URL(s))" in short_raw.stderr


def test_url_cap_keeps_whole_lines_only(monkeypatch) -> None:
    """A count-based cut must never truncate mid-URL and emit a partial one."""
    raw, _procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    for line in raw.stdout.splitlines():
        if line.strip():
            assert line == "https://s.test/a", f"partial URL emitted: {line!r}"


def test_url_limited_output_is_preserved_and_parses(monkeypatch) -> None:
    """Bounded by count is still bounded-and-kept, not discarded."""
    raw, _procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert raw.stdout.strip(), "collected output was discarded"
    findings = katana_runner.KatanaRunner().parse(raw)
    assert findings
    assert all(f.asset_type == "url" for f in findings)


def test_url_limited_run_is_partial_never_completed(monkeypatch) -> None:
    """The status contract is unchanged for the new limit."""
    raw, _procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    assert raw.exit_code != 0
    assert raw.timed_out is False
    assert classify_run(katana_runner.KatanaRunner(), raw, produced_findings=True) == "partial"


def test_url_limited_process_is_terminated_and_reaped(monkeypatch) -> None:
    _raw, procs = _run_short_flood(monkeypatch, config={"max_urls_per_target": 100})
    for proc in procs:
        assert proc.killed >= 1
        assert proc.reaped


def test_reproducibility_records_both_limits(monkeypatch) -> None:
    """A resource_limited run is exactly the case that must be reproducible."""
    raw, _captured = _run_katana(
        monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0,
        config={"max_urls_per_target": 250, "max_stdout_bytes_per_target": 777_000},
    )
    assert "max_urls_per_target=250" in raw.command
    assert "max_stdout_bytes_per_target=777000" in raw.command


def test_a_normal_run_under_both_budgets_still_completes(monkeypatch) -> None:
    """The common path is untouched: output below both limits is a clean success."""
    raw, _captured = _run_katana(
        monkeypatch, stdout=[b"https://a.example/1\nhttps://a.example/2\n"], returncode=0)
    assert raw.exit_code == 0
    assert "exit=resource_limited" not in raw.stderr
    assert classify_run(katana_runner.KatanaRunner(), raw, produced_findings=True) == "completed"
    assert len(katana_runner.KatanaRunner().parse(raw)) == 2


# ==========================================================================================
# jsluice default-off: the root cause of the "full per-target timeout, one URL" runs
# ==========================================================================================
#
# ROOT CAUSE, measured on this worker (katana v1.7.0, identical flags, live authorized
# targets, RSS sampled every 500 ms -- only -jsluice differs):
#
#   target                        -js-crawl -jsluice      -js-crawl only
#   ----------------------------  --------------------    --------------------
#   cpanel.brightvision-og.com    3601 MiB,    1 URL       73 MiB, 2465 URLs
#   webmail.brightvision-og.com   3838 MiB,    1 URL       77 MiB, 2464 URLs
#   www.brightvision-og.com       3740 MiB,    1 URL       53 MiB,    1 URL
#
# The jsluice runs grew ~48 -> 3695 MiB in 5.5s and ended in a cgroup OOM kill (exit 137)
# with stdout still at ONE line. In production this surfaced as `katana.target_timeout ...
# urls_preserved=1` on 30 of 30 timing-out targets: the shared 4 GiB worker cgroup was driven
# to ~100% (memory.pressure full avg10=78.97), which starved every process in the container --
# even `katana -version` took 52-301s there against 48-138 ms on an unpressured worker.
#
# These tests pin the DEFAULT and the opt-in. They do not re-test the output budgets; those
# have their own sections above and are deliberately untouched by this change.

def test_jsluice_is_absent_by_default(monkeypatch) -> None:
    """DEFAULT OFF. Absent from argv entirely -- not passed with a falsy value."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b"https://target.example/a\n"])
    assert "-jsluice" not in cap["command"]


def test_jsluice_default_constant_is_false() -> None:
    """The default is a named constant, so it cannot be flipped by an unrelated edit."""
    assert katana_runner.JSLUICE_DEFAULT is False


def test_jsluice_opt_in_adds_the_flag(monkeypatch) -> None:
    """The CAPABILITY is retained: an explicit config re-enables it."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b""], config={"jsluice": True})
    assert "-jsluice" in cap["command"]


def test_jsluice_falsy_config_keeps_it_off(monkeypatch) -> None:
    """An explicit False stays off (and cannot be read as 'key present => enable')."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b""], config={"jsluice": False})
    assert "-jsluice" not in cap["command"]


def test_js_crawl_stays_on_when_jsluice_is_off(monkeypatch) -> None:
    """COVERAGE IS NOT TRADED AWAY. -js-crawl is what produced the measured 2465 URLs; only
    the pathological parser is off by default."""
    _raw, cap = _run_katana(monkeypatch, stdout=[b""])
    cmd = cap["command"]
    assert "-js-crawl" in cmd
    assert "-jsluice" not in cmd


def test_disabling_jsluice_changes_nothing_else_in_the_command(monkeypatch) -> None:
    """The fix is EXACTLY one flag. Depth, scope, concurrency, parallelism, rate, response
    size, domain pages and crawl-duration are all unchanged -- so this cannot be a silent
    coverage reduction hiding behind a memory fix."""
    _raw, off = _run_katana(monkeypatch, stdout=[b""])
    _raw2, on = _run_katana(monkeypatch, stdout=[b""], config={"jsluice": True})
    assert [c for c in on["command"] if c != "-jsluice"] == off["command"]


def test_jsluice_state_is_recorded_in_the_effective_command(monkeypatch) -> None:
    """REPRODUCIBILITY. orchestrator.py stores RawToolOutput.command as the effective
    command; the flag that decides 3.7 GiB vs 73 MiB has to be visible there."""
    raw_off, _ = _run_katana(monkeypatch, stdout=[b""])
    raw_on, _ = _run_katana(monkeypatch, stdout=[b""], config={"jsluice": True})
    assert "jsluice=False" in raw_off.command
    assert "jsluice=True" in raw_on.command


def test_jsluice_off_does_not_weaken_the_output_budgets(monkeypatch) -> None:
    """The previously VERIFIED protections stay exactly as they were."""
    raw, _ = _run_katana(monkeypatch, stdout=[b""])
    assert katana_runner.MAX_URLS_PER_TARGET == 10_000
    assert katana_runner.MAX_STDOUT_BYTES_PER_TARGET == 5 * 1024 * 1024
    assert katana_runner.MAX_STDERR_BYTES == 1024 * 1024
    assert "max_urls_per_target=10000" in raw.command
    assert "max_stdout_bytes_per_target=5242880" in raw.command


def test_jsluice_off_preserves_one_process_per_target(monkeypatch) -> None:
    """Process isolation is untouched by this change."""
    _raw, rec = _run_multi(monkeypatch, [f"https://h{i}.example" for i in range(5)])
    assert len(rec.launches) == 5
    assert rec.stdins == [f"https://h{i}.example" for i in range(5)]
    for launch in rec.launches:
        assert "-jsluice" not in launch["command"]

# =========== 12. the -jsluice RSS watchdog: per-target containment, not worker recovery =====
#
# WHY THIS SECTION EXISTS. JSLUICE_DEFAULT = False keeps the runaway off the DEFAULT path, but
# `jsluice=True` remains a supported opt-in, and production-equivalent runtime testing proved
# what that opt-in costs: ~4082 MiB peak against a ~4096 MiB worker cgroup, memory.events
# oom 0->2 / oom_kill 0->1, and Docker reporting OOMKilled=true. GOMEMLIMIT=1433 MiB did NOT
# prevent it -- a soft heap ceiling cannot reclaim what is still reachable. The same binary
# with jsluice=False peaked at ~75 MiB.
#
# The kernel's OOM killer chooses its own victim inside that SHARED cgroup, so the cost of one
# opt-in target was a risk to the whole worker. The watchdog makes that cost land on the
# target: the katana child is stopped at its own ceiling, through the existing
# terminate_and_reap path, and classified `resource_limited` with reason `jsluice_rss`.
#
# DETERMINISTIC BY CONSTRUCTION. RSS is injected, not produced: no real katana, no real memory
# pressure, and above all no dependence on the unit suite reproducing an actual 4 GiB OOM.

MIB = 1024 * 1024
GIB = 1024 * MIB


class _AliveStream:
    """Serves its chunks, then blocks forever -- a process that is busy, not finished.

    Returning EOF instead would let the pumps complete and race the watchdog, which is flaky
    in the direction of a false PASS. This models the measured -jsluice shape: it allocated
    for seconds while stdout stayed at one line.
    """

    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, _n: int = -1) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        await asyncio.Event().wait()
        return b""  # pragma: no cover -- unreachable; only the watchdog ends this run


class _WatchedProc:
    """A katana child that emits a little stdout and then stays ALIVE and busy."""

    def __init__(self, pid: int, stdout_chunks=(b"https://partial.example/1\n",)):
        self.pid = pid
        self.stdout = _AliveStream(list(stdout_chunks))
        self.stderr = _AliveStream([])
        self.stdin = _FakeStdin()
        self.returncode = None
        self.killed = 0
        self.reaped = False

    async def wait(self):
        if self.returncode is None:
            self.returncode = -9
        return self.returncode

    def kill(self):
        self.killed += 1
        self.returncode = -9

    async def communicate(self):
        self.reaped = True
        return b"", b""


class _HealthyProc(_FakeProc):
    """A normal fake process that also carries a pid, so a watchdog could sample it."""

    def __init__(self, pid: int, stdout=(b"https://ok.example/1\n",), returncode=0):
        super().__init__(stdout=list(stdout), returncode=returncode)
        self.pid = pid
        self.killed = 0

    def kill(self):
        self.killed += 1
        super().kill()


def _arm(monkeypatch, rss_fn):
    """Point the watchdog at an injected RSS source and sample fast.

    The PRODUCTION interval is asserted separately, in
    test_sampling_interval_is_sized_for_the_measured_growth_rate -- shrinking it here must not
    be able to hide a change to the real one.
    """
    monkeypatch.setattr(base, "read_process_rss_bytes", rss_fn)
    monkeypatch.setattr(base, "RSS_SAMPLE_INTERVAL_SECONDS", 0.001)


def _run_watched(monkeypatch, rss_curve, *, config=None, targets=1,
                 stdout_chunks=(b"https://partial.example/1\n",)):
    """Drive the runner against stalling children with a scripted RSS curve.

    `rss_curve` is the list of values successive samples return FOR EACH process (the last
    value repeats). It is applied per PROCESS rather than per pid on purpose: web_targets()
    expands one bare target into its http:// and https:// forms, so even a "one target" run
    spawns two processes, and a curve keyed on a guessed pid would starve the second one --
    which would hang on a stalling child rather than fail, i.e. fail in the worst direction.

    A None value in the curve models a FAILED read: process gone, /proc unavailable,
    unparsable file. The watchdog must never act on that.
    """
    procs: list = []
    sampled: list[int] = []
    counts: dict = {}

    async def _fake_exec(*command, **kwargs):
        proc = _WatchedProc(4242 + len(procs), stdout_chunks=list(stdout_chunks))
        procs.append(proc)
        return proc

    def _fake_rss(pid: int):
        sampled.append(pid)
        # Only ever answers for a pid this run actually spawned. An unknown pid reads as "no
        # information", exactly as a real failed /proc read would.
        if not any(p.pid == pid for p in procs):
            return None  # pragma: no cover -- the watchdog never samples a foreign pid
        i = counts.get(pid, 0)
        counts[pid] = i + 1
        return rss_curve[min(i, len(rss_curve) - 1)]

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    _arm(monkeypatch, _fake_rss)

    prior = _targets(*[f"https://h{i}.example" for i in range(targets)]) if targets > 1 else []
    raw = asyncio.run(katana_runner.KatanaRunner().run(
        "https://target.example", dict(config or {}), prior))
    return raw, procs, sampled


def _run_healthy(monkeypatch, rss_fn, *, config=None, targets=1):
    """Drive the runner against children that FINISH normally, with RSS injected."""
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        proc = _HealthyProc(5000 + len(procs))
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    _arm(monkeypatch, rss_fn)
    prior = _targets(*[f"https://h{i}.example" for i in range(targets)]) if targets > 1 else []
    raw = asyncio.run(katana_runner.KatanaRunner().run(
        "https://target.example", dict(config or {}), prior))
    return raw, procs


# --- 12.1 the watchdog is armed ONLY for jsluice=True --------------------------------------

def test_jsluice_false_does_not_start_the_rss_watchdog(monkeypatch) -> None:
    """THE default path must be untouched: no watchdog task, not even a passive one.

    Asserted by the ABSENCE of any RSS sample. With jsluice off, run_with_timeout is called
    with max_rss_bytes=None, so no watchdog coroutine is created at all -- which is stronger
    than a watchdog that runs and declines to act, and is what keeps the measured-safe 75 MiB
    path byte-for-byte what it was.
    """
    sampled: list = []

    def _fake_rss(pid: int):
        sampled.append(pid)
        return 1

    _arm(monkeypatch, _fake_rss)
    raw, _captured = _run_katana(monkeypatch, stdout=[b"https://a.example/1\n"], returncode=0)
    assert sampled == [], "the watchdog sampled on the jsluice=False path"
    assert "jsluice=False" in raw.command
    assert "jsluice_rss_limit_enabled=False" in raw.command
    assert "jsluice_max_rss_bytes=disarmed" in raw.command


def test_jsluice_true_enables_the_rss_watchdog(monkeypatch) -> None:
    """The opt-in arms it, against the exact child this runner spawned."""
    raw, procs, sampled = _run_watched(
        monkeypatch, [2 * MIB, 2 * GIB], config={"jsluice": True},
    )
    assert sampled, "the watchdog never sampled with jsluice=True"
    assert set(sampled) <= {p.pid for p in procs}, "a pid we never spawned was sampled"
    assert "jsluice_rss_limit_enabled=True" in raw.command
    assert f"jsluice_max_rss_bytes={katana_runner.JSLUICE_MAX_RSS_BYTES}" in raw.command


# --- 12.2 below the ceiling, nothing is touched --------------------------------------------

def test_rss_below_the_ceiling_does_not_terminate_the_process(monkeypatch) -> None:
    """A legitimate jsluice crawl must not be killed. It ends on its own terms, exit 0."""
    raw, procs = _run_healthy(
        monkeypatch, lambda pid: 200 * MIB, config={"jsluice": True},
    )
    assert "exit=resource_limited" not in raw.stderr
    assert katana_runner.JSLUICE_RSS_LIMIT_REASON not in raw.stderr
    assert "jsluice_rss_limit_tripped=False" in raw.command
    assert raw.exit_code == 0
    for proc in procs:
        assert proc.killed == 0, "a healthy jsluice crawl was killed"
        assert proc.returncode == 0


def test_rss_exactly_at_the_ceiling_is_not_a_kill(monkeypatch) -> None:
    """The bound is EXCEEDS, not reaches -- a process sitting exactly on its budget is
    within it, the same rule the output budgets follow."""
    raw, procs = _run_healthy(
        monkeypatch,
        lambda pid: katana_runner.JSLUICE_MAX_RSS_BYTES,
        config={"jsluice": True},
    )
    assert "exit=resource_limited" not in raw.stderr
    for proc in procs:
        assert proc.killed == 0


# --- 12.3 above the ceiling, that process and ONLY that process is stopped -----------------

def test_rss_above_the_ceiling_terminates_the_katana_process(monkeypatch) -> None:
    """THE fix: the runaway is stopped by this runner, before the cgroup notices."""
    _raw, procs, _sampled = _run_watched(
        monkeypatch,
        # The measured curve, compressed: healthy, climbing, then past the ceiling.
        [48 * MIB, 700 * MIB, 3 * GIB],
        config={"jsluice": True},
    )
    assert procs[0].killed >= 1, "the runaway katana process was not terminated"


def test_only_the_offending_katana_process_is_terminated(monkeypatch) -> None:
    """Per-target containment. The other targets still run, untouched and unsignalled."""
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        proc = _WatchedProc(4242) if not procs else _HealthyProc(4300 + len(procs))
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    _arm(monkeypatch, lambda pid: 3 * GIB if pid == 4242 else 50 * MIB)
    raw = asyncio.run(katana_runner.KatanaRunner().run(
        "https://target.example", {"jsluice": True},
        _targets("https://a.example", "https://b.example", "https://c.example"),
    ))

    assert len(procs) == 3, "the runaway stopped the other targets from being attempted"
    assert procs[0].killed >= 1
    # The healthy ones exited on their OWN terms and were never signalled.
    assert procs[1].killed == 0 and procs[2].killed == 0
    assert procs[1].returncode == 0 and procs[2].returncode == 0
    assert "https://ok.example/1" in raw.stdout


def test_the_watchdog_only_ever_reads_its_own_childs_pid(monkeypatch) -> None:
    """It must be INCAPABLE of selecting an unrelated victim.

    The only pid it may read is the one it was handed. Nothing else in the container -- the
    worker itself, a sibling katana, a Chromium screenshot instance -- is even observed, so
    there is no pid it could act on but this one.
    """
    _raw, procs, sampled = _run_watched(
        monkeypatch, [10 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert sampled, "nothing was sampled"
    assert set(sampled) <= {p.pid for p in procs}
    assert 4242 in set(sampled)


# --- 12.4 the outcome: resource-limited, DISTINCT reason, never a timeout ------------------

def test_rss_kill_is_recorded_with_the_jsluice_rss_reason(monkeypatch) -> None:
    """The reason is `jsluice_rss`, distinct from the output budgets AND from a timeout."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert katana_runner.JSLUICE_RSS_LIMIT_REASON == "jsluice_rss"
    assert f"reason={katana_runner.JSLUICE_RSS_LIMIT_REASON}" in raw.stderr
    assert "exit=resource_limited" in raw.stderr
    assert "jsluice_rss_limit_tripped=True" in raw.command
    assert f"jsluice_rss_reason={katana_runner.JSLUICE_RSS_LIMIT_REASON}" in raw.command


def test_rss_kill_is_not_classified_as_a_timeout(monkeypatch) -> None:
    """NOT a timeout. An operator told 'timed out' would raise a deadline that was never the
    constraint, and would leave the memory runaway exactly where it was."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert raw.timed_out is False
    assert "timed out" not in raw.stderr


def test_rss_kill_does_not_wait_for_the_per_target_deadline(monkeypatch) -> None:
    """It fires on the SAMPLE, not on the clock.

    The per-target deadline here is hundreds of seconds; this completes in milliseconds, which
    is only possible if the watchdog -- not the deadline -- ended the run.
    """
    started = time.monotonic()
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    elapsed = time.monotonic() - started
    assert "exit=resource_limited" in raw.stderr
    assert katana_runner.compute_per_target_timeout(None) > 100, "no deadline to outrun"
    assert elapsed < 30, f"the run waited on a deadline rather than the watchdog ({elapsed}s)"


def test_rss_kill_is_never_a_successful_completed_run(monkeypatch) -> None:
    """A contained runaway is PARTIAL. It must never read as a clean crawl."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert raw.exit_code != 0
    assert "0 completed" in raw.stderr
    assert classify_run(katana_runner.KatanaRunner(), raw, produced_findings=True) == "partial"


def test_rss_kill_summary_names_the_memory_ceiling_not_an_output_budget(monkeypatch) -> None:
    """The remedy differs: drop -jsluice for this target, do NOT raise an output cap."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert "-jsluice memory ceiling" in raw.stderr
    assert "NOT proven absent" in raw.stderr


# --- 12.5 partial output survives, and the process is fully reaped -------------------------

def test_partial_stdout_is_preserved_across_an_rss_kill(monkeypatch) -> None:
    """The URLs crawled before the ceiling are kept and remain parseable downstream."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
        stdout_chunks=(b"https://partial.example/1\nhttps://partial.example/2\n",),
    )
    assert "https://partial.example/1" in raw.stdout
    assert "https://partial.example/2" in raw.stdout
    values = {f.value for f in katana_runner.KatanaRunner().parse(raw)}
    assert "https://partial.example/1" in values
    assert "https://partial.example/2" in values


def test_the_rss_killed_process_is_fully_reaped(monkeypatch) -> None:
    """No zombie, no orphan: termination goes through the existing terminate_and_reap."""
    _raw, procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert procs[0].killed >= 1
    assert procs[0].reaped, "the process was killed but never reaped"
    assert procs[0].returncode is not None


def test_peak_rss_is_recorded_for_reproducibility(monkeypatch) -> None:
    """The provenance record carries the number the ceiling was compared against."""
    raw, _procs, _sampled = _run_watched(
        monkeypatch, [48 * MIB, 700 * MIB, 3 * GIB], config={"jsluice": True},
    )
    assert "peak_rss_bytes=" in raw.command
    assert "peak_rss_bytes=unmeasured" not in raw.command
    assert "peak RSS" in raw.stderr


# --- 12.6 failure modes of the MONITOR ITSELF must be safe ---------------------------------

def test_a_process_disappearing_mid_sample_is_handled_safely(monkeypatch) -> None:
    """The child exits between the decision to sample and the read: None, not a crash."""
    # The real read path against a pid that cannot exist -- not the injected one.
    assert base.read_process_rss_bytes(2_147_483_646) is None

    raw, procs = _run_healthy(monkeypatch, lambda pid: None, config={"jsluice": True})
    assert raw.exit_code == 0, "a vanished process was treated as a failure"
    assert "exit=resource_limited" not in raw.stderr
    assert procs[0].killed == 0
    assert "peak_rss_bytes=unmeasured" in raw.command


def test_an_rss_read_failure_can_never_kill_anything(monkeypatch) -> None:
    """A watchdog that killed on a failed read would be worse than the bug it guards against.

    Every read fails for the whole run here. The process must be left entirely alone, and the
    run must be indistinguishable from one where no guard was armed.
    """
    raw, procs = _run_healthy(monkeypatch, lambda pid: None, config={"jsluice": True})
    assert procs[0].killed == 0
    assert procs[0].returncode == 0
    assert "exit=resource_limited" not in raw.stderr
    assert raw.exit_code == 0


def test_rss_reader_never_raises_on_an_unreadable_pid() -> None:
    """Its contract is 'returns None, never raises', for every failure mode."""
    for pid in (-1, 0, 2_147_483_646):
        assert base.read_process_rss_bytes(pid) is None


def test_rss_reader_parses_a_real_proc_status_shape(tmp_path, monkeypatch) -> None:
    """The VmRSS line is parsed in kB and returned in bytes."""
    status = tmp_path / "status"
    status.write_text(
        "Name:\tkatana\nState:\tR (running)\nVmPeak:\t 4194304 kB\nVmRSS:\t 1048576 kB\n"
    )
    real_open = open

    def _fake_open(path, *a, **kw):
        if str(path) == "/proc/424242/status":
            return real_open(status, *a, **kw)
        return real_open(path, *a, **kw)  # pragma: no cover

    monkeypatch.setattr("builtins.open", _fake_open)
    assert base.read_process_rss_bytes(424242) == 1048576 * 1024


def test_rss_reader_returns_none_for_a_malformed_vmrss_line(tmp_path, monkeypatch) -> None:
    """Garbage is 'no information', not an exception and above all not a kill."""
    status = tmp_path / "status"
    status.write_text("Name:\tkatana\nVmRSS:\tnot-a-number kB\n")
    real_open = open

    def _fake_open(path, *a, **kw):
        if str(path) == "/proc/424243/status":
            return real_open(status, *a, **kw)
        return real_open(path, *a, **kw)  # pragma: no cover

    monkeypatch.setattr("builtins.open", _fake_open)
    assert base.read_process_rss_bytes(424243) is None


def test_an_invalid_rss_ceiling_is_rejected_before_any_process_spawns(monkeypatch) -> None:
    """A safety control validated like the others: 0 must not be read as 'unlimited'."""
    spawned: list = []

    async def _fake_exec(*command, **kwargs):
        spawned.append(command)
        return _FakeProc(stdout=[b""], returncode=0)

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    with pytest.raises(katana_runner.KatanaBudgetError):
        asyncio.run(katana_runner.KatanaRunner().run(
            "https://target.example",
            {"jsluice": True, "jsluice_max_rss_bytes": 0}, []))
    assert spawned == []


# --- 12.7 the ceiling and the interval are the MEASURED values -----------------------------

def test_the_rss_ceiling_sits_far_below_the_worker_cgroup() -> None:
    """1 GiB against a ~4096 MiB worker cgroup.

    A ceiling near 4 GiB would trip at the same moment the kernel does -- i.e. it would be no
    ceiling at all. This pins the HEADROOM, not just the number: the worker's Python process,
    Redis/Celery state, other per-target buffers and kernel page accounting all live under the
    same wall, so katana's share is not the wall.
    """
    assert katana_runner.JSLUICE_MAX_RSS_BYTES == 1024 * 1024 * 1024
    worker_cgroup = 4096 * MIB
    assert katana_runner.JSLUICE_MAX_RSS_BYTES <= worker_cgroup // 4
    # And far enough ABOVE a healthy run (~75 MiB measured) not to truncate real crawls.
    assert katana_runner.JSLUICE_MAX_RSS_BYTES >= 10 * 75 * MIB


def test_sampling_interval_is_sized_for_the_measured_growth_rate() -> None:
    """~660 MiB/s was measured (48 -> 3695 MiB in 5.5s).

    The worst-case overshoot between the last sample below the ceiling and the one that trips
    it is rate x interval, and it has to stay small against the headroom below the wall --
    otherwise the ceiling is nominal and the kernel still wins the race.
    """
    interval = base.RSS_SAMPLE_INTERVAL_SECONDS
    assert 0 < interval <= 0.5, "too coarse to catch a ~660 MiB/s runaway"
    overshoot = 660 * MIB * interval
    headroom = 4096 * MIB - katana_runner.JSLUICE_MAX_RSS_BYTES
    assert overshoot < headroom / 4


# --- 12.8 NOTHING ELSE MOVED ---------------------------------------------------------------

def test_existing_url_and_stdout_budgets_are_unchanged_by_the_watchdog(monkeypatch) -> None:
    """The 10,000 URL and 5 MiB limits are exactly what the earlier validation exercised."""
    assert katana_runner.MAX_URLS_PER_TARGET == 10_000
    assert katana_runner.MAX_STDOUT_BYTES_PER_TARGET == 5 * 1024 * 1024
    for cfg in ({}, {"jsluice": True}):
        raw, _captured = _run_katana(monkeypatch, stdout=[b""], config=cfg)
        assert "max_urls_per_target=10000" in raw.command
        assert "max_stdout_bytes_per_target=5242880" in raw.command


def test_js_crawl_stays_enabled_with_the_watchdog_armed(monkeypatch) -> None:
    """-js-crawl is the source of the measured coverage and is NOT what this change touches."""
    for cfg in ({}, {"jsluice": True}):
        _raw, captured = _run_katana(monkeypatch, stdout=[b""], config=cfg)
        assert "-js-crawl" in captured["command"]


def test_the_watchdog_introduces_no_argv_change_at_all(monkeypatch) -> None:
    """THE invariant: argv still differs ONLY by -jsluice. The RSS guard is runner-side."""
    _raw_off, off = _run_katana(monkeypatch, stdout=[b""])
    _raw_on, on = _run_katana(monkeypatch, stdout=[b""], config={"jsluice": True})
    assert [c for c in on["command"] if c != "-jsluice"] == off["command"]
    assert on["command"].count("-jsluice") == 1
    # And nothing named after the guard leaked into argv.
    for arg in on["command"]:
        assert "rss" not in arg.lower()


def test_one_process_per_target_isolation_survives_the_watchdog(monkeypatch) -> None:
    """Process isolation is the mechanism the watchdog plugs INTO, not one it replaces."""
    urls = [f"https://h{i}.example" for i in range(4)]
    procs: list = []

    async def _fake_exec(*command, **kwargs):
        proc = _HealthyProc(5000 + len(procs))
        procs.append(proc)
        return proc

    monkeypatch.setattr(katana_runner.asyncio, "create_subprocess_exec", _fake_exec)
    _arm(monkeypatch, lambda pid: 50 * MIB)
    asyncio.run(katana_runner.KatanaRunner().run(
        "https://target.example", {"jsluice": True}, _targets(*urls)))

    assert len(procs) == 4, "one process per target no longer holds"
    assert [p.stdin.written.decode() for p in procs] == urls


def test_the_default_path_reports_no_rss_guard_in_provenance(monkeypatch) -> None:
    """jsluice=False must still be describable as the untouched, measured-safe path."""
    raw, _captured = _run_katana(monkeypatch, stdout=[b""])
    assert "jsluice=False" in raw.command
    assert "jsluice_rss_limit_enabled=False" in raw.command
    assert "jsluice_rss_limit_tripped=False" in raw.command
    assert "jsluice_rss_reason=none" in raw.command
