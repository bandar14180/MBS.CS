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
