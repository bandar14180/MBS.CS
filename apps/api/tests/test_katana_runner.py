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

from apps.api.scanner_engine.tool_runners import katana_runner
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
    for flag in ("-silent", "-no-color", "-depth", "-js-crawl", "-jsluice",
                 "-field-scope", "-concurrency", "-parallelism", "-rate-limit", "-timeout"):
        assert flag in cmd, f"{flag} missing from katana invocation"
    # JS crawling must stay on: it is what surfaces API endpoints for the DAST runner.
    assert "-js-crawl" in cmd and "-jsluice" in cmd
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

def test_js_crawl_and_jsluice_present_in_every_invocation(monkeypatch) -> None:
    """The capabilities this fix must not trade away, asserted per PROCESS."""
    _raw, rec = _run_multi(monkeypatch, [f"https://h{i}.example" for i in range(4)])
    for launch in rec.launches:
        assert "-js-crawl" in launch["command"]
        assert "-jsluice" in launch["command"]


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
        assert "-js-crawl" in cmd and "-jsluice" in cmd


def test_gomemlimit_env_is_passed_to_every_process(monkeypatch) -> None:
    monkeypatch.setattr(katana_runner, "_cgroup_memory_max_bytes", lambda: 4 * 1024**3)
    _raw, rec = _run_multi(monkeypatch, ["https://a.example", "https://b.example"])
    for launch in rec.launches:
        assert launch["env"]["GOMEMLIMIT"] == "1433MiB"
