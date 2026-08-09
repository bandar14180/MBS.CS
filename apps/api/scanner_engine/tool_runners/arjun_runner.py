import asyncio
import json
import os
import tempfile

from apps.api.scanner_engine.tool_runners._web import param_discovery_targets
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, CommonFinding, RawToolOutput

DEFAULT_TIMEOUT_SECONDS = 480  # arjun sends a large param wordlist per URL -- slow
MAX_PARAMS_PER_URL = 15        # cap so a synthesised URL doesn't get absurdly long


class ArjunRunner(BaseToolRunner):
    """HTTP parameter discovery (arjun). The crawler finds endpoint *paths*, but a
    JSON API's parameter *names* (e.g. ?q=, ?file=, ?id=) live in JS that builds
    the request dynamically, so a plain crawl misses them -- and a fuzzer with no
    parameter has nothing to inject. arjun brute-forces valid parameter names per
    endpoint, and we emit `url` findings carrying those params so nuclei-dast can
    then fuzz them. This is what turns discovered API paths into fuzzable targets."""

    name = "arjun"
    version = "2.2.7"
    requires_active_testing = True  # actively probes endpoints with a param wordlist -> gated
    phase = 48  # after katana (45) has the endpoints, before nuclei-dast (55) fuzzes them
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # benign GET probes to enumerate params (no state change)
    applicable_target_types = {"domain", "ip_range"}

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = param_discovery_targets(prior_findings, config.get("param_discovery_max", 10))
        if not targets:
            return RawToolOutput(command="arjun (no endpoints to probe)", stdout="", stderr="no endpoints", exit_code=0)

        in_fd, in_path = tempfile.mkstemp(suffix=".txt")
        out_path = in_path + ".json"
        try:
            with os.fdopen(in_fd, "w") as f:
                f.write("\n".join(targets))

            command = ["arjun", "-i", in_path, "-oJ", out_path, "-m", "GET", "-T", "10"]
            proc = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=config.get("param_discovery_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                return RawToolOutput(command=" ".join(command), stdout="", stderr="timed out", exit_code=-1)

            # arjun's useful output is the JSON file, not stdout -- surface it as the
            # run's stdout so parse() (and the stored evidence) work the usual way.
            result_json = ""
            if os.path.exists(out_path):
                with open(out_path, encoding="utf-8", errors="replace") as f:
                    result_json = f.read()

            return RawToolOutput(
                command=" ".join(command) + f"  (probed {len(targets)} endpoint(s))",
                stdout=result_json,
                stderr=stderr.decode(errors="replace")[-500:],
                exit_code=proc.returncode if proc.returncode is not None else -1,
            )
        finally:
            for p in (in_path, out_path):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        """Turn arjun's {url: {params: [...]}} into parameterised `url` findings
        (url?p1=1&p2=1...) that the DAST runner will fuzz."""
        if not raw.stdout.strip():
            return []
        try:
            data = json.loads(raw.stdout)
        except json.JSONDecodeError:
            return []

        findings: list[CommonFinding] = []
        for url, info in (data.items() if isinstance(data, dict) else []):
            params = (info or {}).get("params") if isinstance(info, dict) else None
            if not params:
                continue
            query = "&".join(f"{p}=1" for p in params[:MAX_PARAMS_PER_URL])
            sep = "&" if "?" in url else "?"
            findings.append(
                CommonFinding(
                    asset_type="url",
                    value=f"{url}{sep}{query}",
                    metadata={"has_params": True, "source": "arjun", "params": params[:MAX_PARAMS_PER_URL]},
                )
            )
        return findings
