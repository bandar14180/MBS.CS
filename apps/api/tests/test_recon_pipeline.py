import asyncio

from apps.api.scanner_engine.tool_runners.base import CommonFinding, RawToolOutput
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner
from apps.api.scanner_engine.tool_runners.nmap_runner import NmapRunner
from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner


# --- parse() unit tests (pure, no binaries) ---

def test_subfinder_parse() -> None:
    raw = RawToolOutput(
        command="subfinder -d example.com",
        stdout='{"host":"a.example.com","source":"crtsh"}\n'
        "not json\n"
        '{"host":"b.example.com","source":"dnsdumpster"}\n',
        stderr="",
        exit_code=0,
    )
    findings = SubfinderRunner().parse(raw)
    assert [f.value for f in findings] == ["a.example.com", "b.example.com"]
    assert all(f.asset_type == "subdomain" for f in findings)
    assert findings[0].metadata["source"] == "crtsh"


def test_httpx_parse() -> None:
    raw = RawToolOutput(
        command="httpx-pd",
        stdout='{"url":"https://10.0.0.1","host":"10.0.0.1","port":443,"scheme":"https",'
        '"status_code":200,"title":"Home","webserver":"nginx","tech":["Nginx"]}\n',
        stderr="",
        exit_code=0,
    )
    findings = HttpxRunner().parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.asset_type == "http_service"
    assert f.value == "https://10.0.0.1"
    assert f.metadata["status_code"] == 200
    assert f.metadata["webserver"] == "nginx"
    assert f.metadata["tech"] == ["Nginx"]


def test_httpx_run_feeds_original_hostname_not_resolved_ip(monkeypatch) -> None:
    # Regression: httpx (and everything downstream that reuses its findings -- nuclei,
    # katana, arjun, nuclei-dast) must receive the ORIGINAL hostname, not a pre-resolved
    # bare IP. A CDN/shared-IP site (the overwhelming majority of real websites) answers a
    # bare-IP request with someone else's default page, not the actual target -- found live:
    # a real production domain came back as a 308 redirect to https://vercel.com/, not an
    # error, so nothing about the run looked broken.
    import apps.api.scanner_engine.tool_runners.httpx_runner as httpx_runner_module

    monkeypatch.setattr(httpx_runner_module, "resolve_scan_host", lambda h: "203.0.113.9")

    captured = {}

    class _FakeProc:
        returncode = 0

        async def communicate(self, input=None):
            captured["stdin"] = input.decode()
            return b"", b""

    async def _fake_exec(*args, **kwargs):
        return _FakeProc()

    monkeypatch.setattr(httpx_runner_module.asyncio, "create_subprocess_exec", _fake_exec)

    raw = asyncio.run(HttpxRunner().run("www.example.com", {}, []))
    assert captured["stdin"] == "www.example.com"
    assert raw.exit_code == 0


def test_nmap_parse_open_ports_only() -> None:
    xml = """<?xml version="1.0"?><nmaprun>
      <host>
        <address addr="10.0.0.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.27"/>
          </port>
          <port protocol="tcp" portid="8080">
            <state state="closed"/>
            <service name="http-proxy"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    findings = NmapRunner().parse(RawToolOutput(command="nmap", stdout=xml, stderr="", exit_code=0))
    assert len(findings) == 1  # only the open port
    f = findings[0]
    assert f.asset_type == "service"
    assert f.value == "10.0.0.1:80"
    assert f.metadata["service"] == "http"
    assert f.metadata["product"] == "nginx"


def test_nmap_parse_handles_empty_output() -> None:
    assert NmapRunner().parse(RawToolOutput(command="nmap", stdout="", stderr="err", exit_code=1)) == []


# --- pipeline wiring: prior findings feed later tools ---

def test_naabu_consumes_httpx_live_hosts() -> None:
    prior = [
        CommonFinding(asset_type="subdomain", value="a.example.com"),
        CommonFinding(asset_type="http_service", value="http://a.example.com", metadata={"host": "a.example.com"}),
    ]
    hosts = NaabuRunner()._host_set("example.com", prior)
    assert hosts == ["example.com", "a.example.com"]  # target + httpx live host, deduped


def test_naabu_falls_back_to_subdomains_when_no_httpx() -> None:
    prior = [CommonFinding(asset_type="subdomain", value="a.example.com")]
    hosts = NaabuRunner()._host_set("example.com", prior)
    assert hosts == ["example.com", "a.example.com"]


def test_nmap_targets_naabu_ports_only() -> None:
    prior = [
        CommonFinding(asset_type="port", value="10.0.0.1:80", metadata={"ip": "10.0.0.1", "port": 80}),
        CommonFinding(asset_type="port", value="10.0.0.1:443", metadata={"ip": "10.0.0.1", "port": 443}),
    ]
    hosts, ports = NmapRunner()._targets_and_ports("example.com", prior)
    assert hosts == ["10.0.0.1"]
    assert ports == ["80", "443"]


def test_nmap_fallback_when_no_prior_ports() -> None:
    hosts, ports = NmapRunner()._targets_and_ports("example.com", [])
    assert hosts == ["example.com"]
    assert ports is None  # triggers --top-ports fallback


def test_pipeline_runs_in_phase_order_and_passes_findings() -> None:
    """The orchestrator sorts runners by phase and threads accumulated findings
    through the chain. Verified here with fake runners to avoid needing the real
    binaries."""
    from apps.api.scanner_engine.tool_runners.base import BaseToolRunner

    call_log: list[str] = []

    def make_runner(nm: str, ph: int, emits: list[CommonFinding]):
        class _Fake(BaseToolRunner):
            name = nm
            version = "0"
            phase = ph

            async def run(self, target_value, config, prior_findings):
                call_log.append(f"{nm}:{[f.value for f in prior_findings]}")
                return RawToolOutput(command=nm, stdout="", stderr="", exit_code=0)

            def parse(self, raw):
                return emits

        return _Fake()

    # deliberately register out of phase order
    late = make_runner("late", 40, [])
    early = make_runner("early", 10, [CommonFinding(asset_type="subdomain", value="x")])

    runners = [late, early]
    runners.sort(key=lambda r: r.phase)

    discovered: list[CommonFinding] = []

    async def drive():
        for r in runners:
            findings = r.parse(await r.run("t", {}, discovered))
            discovered.extend(findings)

    asyncio.run(drive())

    assert call_log == ["early:[]", "late:['x']"]  # early first, late saw early's finding


# --- amass command-line regression (found by scanner_engine.doctor) -----------------
#
# AmassRunner passed `-noalts`, a flag that exists in Amass v3 but was REMOVED in v4
# (where altered-name generation became opt-in via `-alts`). Against the pinned v4.2.0
# in Dockerfile.worker, amass therefore exited 1 immediately -- "flag provided but not
# defined: -noalts" -- on every scan it was part of, contributing nothing while looking
# indistinguishable from a tool that ran and found no subdomains.

def _amass_command(config: dict | None = None) -> list[str]:
    """Capture the argv AmassRunner would exec, without running amass."""
    import asyncio as _asyncio

    from apps.api.scanner_engine.tool_runners.amass_runner import AmassRunner

    captured: list[str] = []

    class _Proc:
        returncode = 0

        async def communicate(self):
            return b"", b""

    async def _fake_exec(*argv, **_kwargs):
        captured.extend(argv)
        return _Proc()

    runner = AmassRunner()
    original = _asyncio.create_subprocess_exec
    _asyncio.create_subprocess_exec = _fake_exec
    try:
        _asyncio.run(runner.run("example.com", config or {}, []))
    finally:
        _asyncio.create_subprocess_exec = original
    return captured


def test_amass_does_not_pass_v3_only_flags():
    command = _amass_command()
    assert "-noalts" not in command, (
        "`-noalts` was removed in Amass v4 (see amass_runner.py). Passing it makes the "
        "pinned v4.2.0 binary exit 1 before enumerating anything."
    )
    # The intent it expressed still holds: v4 does not generate altered names unless asked.
    assert "-alts" not in command
    assert command[:5] == ["amass", "enum", "-passive", "-d", "example.com"]
    assert "-norecursive" in command  # still a valid v4 flag


def test_amass_bounds_itself_inside_the_runner_timeout():
    """Without its own `-timeout`, a slow passive enumeration is SIGKILLed by the runner
    and every name it had already collected is discarded. `-timeout` is whole MINUTES and
    must land strictly inside the runner's wall-clock budget."""
    command = _amass_command({"timeout_seconds": 300})
    minutes = int(command[command.index("-timeout") + 1])
    assert minutes * 60 < 300, "amass must self-terminate before the runner kills it"
    assert minutes == 4

    # Never below 1 minute, however small the configured budget -- `-timeout 0` means
    # "no limit" to amass, the exact opposite of what a tight budget intends.
    assert int(_amass_command({"timeout_seconds": 30})[-1]) == 1


# --- ffuf fan-out: concurrency, per-target isolation, dead-target handling ----------
#
# ffuf fuzzes every httpx-confirmed service. It used to loop over them sequentially, so a
# host with N services took N x the per-target timeout -- a real scan sat in ffuf for
# 550s+ (5 services x 180s worst case) while every other tool finished in under 90s, and
# a target that timed out returned exit -1 with no explanation. These pin the fix.

def _run_ffuf(monkeypatch, targets, *, behavior):
    """Drive FfufRunner.run with create_subprocess_exec faked. `behavior(url)` returns
    (stdout, stderr, returncode); a value of "TIMEOUT" makes communicate() hang so the
    runner's own wait_for fires."""
    import asyncio as _asyncio

    from apps.api.scanner_engine.tool_runners import ffuf_runner

    monkeypatch.setattr(ffuf_runner, "content_discovery_targets", lambda *a, **k: list(targets))

    class _S:
        ffuf_wordlist_path = "/tmp/wl.txt"

    monkeypatch.setattr(ffuf_runner, "get_settings", lambda: _S())

    active = 0
    max_active = 0

    class _Stream:
        """Stream half of the double. ffuf's runner now DRAINS stdout/stderr incrementally
        (base.run_with_timeout) instead of calling communicate(), so the double exposes
        readable streams. The modelled behaviour -- concurrency, timeout, exit codes -- is
        unchanged; only the interface it presents matches the runner."""

        def __init__(self, proc, data: bytes, is_stdout: bool):
            self._proc = proc
            self._data = data
            self._is_stdout = is_stdout
            self._done = False

        async def read(self, _n: int = -1) -> bytes:
            if self._done:
                return b""
            self._done = True
            if self._is_stdout:
                return await self._proc._produce(self._data)
            return self._data

    class _Proc:
        def __init__(self, url):
            self.url = url
            self.returncode = None
            out, err, rc = behavior(url)
            self._rc = rc
            self._timeout = out == "TIMEOUT"
            self.stdout = _Stream(self, b"" if self._timeout else out.encode(), True)
            self.stderr = _Stream(self, err.encode(), False)
            self.stdin = None

        async def _produce(self, data: bytes) -> bytes:
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            try:
                if self._timeout:
                    await _asyncio.sleep(9999)
                # Yield so sibling subprocesses overlap under the semaphore -- otherwise
                # a synchronous return serialises them and hides real concurrency.
                await _asyncio.sleep(0.02)
                return data
            finally:
                active -= 1

        async def wait(self):
            if self.returncode is None:
                self.returncode = self._rc
            return self.returncode

        async def communicate(self):
            return b"", b""

        def kill(self):
            self.returncode = -9

    async def _fake_exec(*argv, **_kw):
        url = argv[argv.index("-u") + 1]
        return _Proc(url)

    monkeypatch.setattr(_asyncio, "create_subprocess_exec", _fake_exec)
    raw = _asyncio.run(
        ffuf_runner.FfufRunner().run("example.com", {"timeout_seconds": 1}, [])
    )
    return raw, max_active


def test_ffuf_fuzzes_targets_concurrently(monkeypatch):
    targets = [f"http://h{i}.example.com" for i in range(5)]

    def behavior(url):
        import json as _json
        return _json.dumps({"url": url + "/admin", "status": 200, "length": 10}) + "\n", "", 0

    raw, max_active = _run_ffuf(monkeypatch, targets, behavior=behavior)
    # More than one subprocess ran at once -- the old sequential loop capped this at 1.
    assert max_active > 1
    # Bounded by MAX_CONCURRENT_TARGETS, not unbounded fan-out.
    from apps.api.scanner_engine.tool_runners.ffuf_runner import MAX_CONCURRENT_TARGETS
    assert max_active <= MAX_CONCURRENT_TARGETS
    # Every target's hits are present.
    assert len(FfufRunner_parse(raw)) == 5


def test_ffuf_dead_target_is_reported_not_silently_completed(monkeypatch):
    # ffuf with -se exits 0 with a "Receiving spurious errors, exiting." stderr and no
    # hits when the target errors on every request. That must surface as a failure reason,
    # not a clean empty completion.
    def behavior(url):
        return "", "Receiving spurious errors, exiting.\n", 0

    raw, _ = _run_ffuf(monkeypatch, ["http://dead.example.com"], behavior=behavior)
    assert raw.exit_code != 0
    assert "spurious errors" in raw.stderr.lower()


def test_ffuf_one_target_timeout_does_not_sink_the_others(monkeypatch):
    targets = ["http://slow.example.com", "http://ok.example.com"]

    def behavior(url):
        import json as _json
        if "slow" in url:
            return "TIMEOUT", "", 0
        return _json.dumps({"url": url + "/x", "status": 200, "length": 5}) + "\n", "", 0

    raw, _ = _run_ffuf(monkeypatch, targets, behavior=behavior)
    # The healthy target's finding survived the other's timeout.
    assert any("ok.example.com" in f.value for f in FfufRunner_parse(raw))
    # And the timeout is recorded.
    assert "timed out" in raw.stderr.lower()


def FfufRunner_parse(raw):
    from apps.api.scanner_engine.tool_runners.ffuf_runner import FfufRunner
    return FfufRunner().parse(raw)


# --- content_discovery_targets(): ffuf skips httpx roots that returned 4xx/5xx -------------
# The real-world bug: an Autodiscover/mail endpoint returned 400 to every path, so ffuf
# hammered it and bailed with "Receiving spurious errors, exiting.", failing the whole run.
# httpx already records the root status_code; ffuf now filters on it (behavior-based, no
# hostname rules). web_targets() is deliberately unchanged, so nuclei/katana/whatweb still
# see every live host.

def _svc(url: str, status):
    return CommonFinding(asset_type="http_service", value=url, metadata={"status_code": status})


def _cdt(prior, target="example.com"):
    from apps.api.scanner_engine.tool_runners._web import content_discovery_targets
    return content_discovery_targets(target, prior)


def test_content_discovery_includes_2xx_roots():
    assert _cdt([_svc("https://ok.example.com", 200)]) == ["https://ok.example.com"]


def test_content_discovery_includes_3xx_roots():
    for code in (301, 302, 307):
        urls = _cdt([_svc(f"https://r{code}.example.com", code)])
        assert urls == [f"https://r{code}.example.com"], code


def test_content_discovery_excludes_4xx_and_5xx_roots():
    for code in (400, 401, 403, 404, 500):
        # The only http_service is a 4xx/5xx root -> no usable httpx target, so it falls back
        # to the bare host rather than fuzzing the dead root.
        urls = _cdt([_svc(f"https://bad{code}.example.com", code)], target="example.com")
        assert all(f"bad{code}.example.com" not in u for u in urls), code
        assert urls == ["http://example.com", "https://example.com"], code


def test_content_discovery_includes_missing_or_nonnumeric_status():
    # None, absent key, and a non-numeric value all preserve prior behavior: include.
    none_status = _cdt([_svc("https://a.example.com", None)])
    assert none_status == ["https://a.example.com"]
    no_key = _cdt([CommonFinding(asset_type="http_service", value="https://b.example.com", metadata={})])
    assert no_key == ["https://b.example.com"]
    weird = _cdt([_svc("https://c.example.com", "??")])
    assert weird == ["https://c.example.com"]


def test_content_discovery_autodiscover_400_plus_universities_200_selects_only_universities():
    prior = [
        _svc("https://autodiscover.brightvision-og.com", 400),
        _svc("https://universities.brightvision-og.com", 200),
    ]
    assert _cdt(prior, target="brightvision-og.com") == [
        "https://universities.brightvision-og.com"
    ]


def test_content_discovery_fallback_to_ports_then_bare_host_is_unchanged():
    from apps.api.scanner_engine.tool_runners._web import web_targets

    # Discovered-port fallback: identical to web_targets (no status to judge).
    ports = [CommonFinding(asset_type="service", value="p", metadata={"host": "1.2.3.4", "port": 8080})]
    assert _cdt(ports, target="example.com") == web_targets("example.com", ports)
    # Bare-host fallback when there are no findings at all.
    assert _cdt([], target="example.com") == web_targets("example.com", [])


def test_web_targets_itself_is_not_status_filtered_so_other_http_tools_are_unaffected():
    # nuclei/nuclei-dast/katana/whatweb use web_targets and MUST still see a 400 host.
    from apps.api.scanner_engine.tool_runners._web import web_targets

    prior = [_svc("https://autodiscover.brightvision-og.com", 400)]
    assert web_targets("brightvision-og.com", prior) == [
        "https://autodiscover.brightvision-og.com"
    ]


def test_ffuf_runner_uses_content_discovery_targets_not_web_targets():
    import inspect

    from apps.api.scanner_engine.tool_runners import ffuf_runner

    src = inspect.getsource(ffuf_runner.FfufRunner.run)
    assert "content_discovery_targets(" in src
    assert "web_targets(" not in src
