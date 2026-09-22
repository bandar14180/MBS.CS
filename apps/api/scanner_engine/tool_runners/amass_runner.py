import asyncio

from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

DEFAULT_TIMEOUT_SECONDS = 180


class AmassRunner(BaseToolRunner):
    """Passive subdomain enumeration (OWASP Amass). A second, independent
    implementation of `subdomain_discovery` alongside subfinder: a different set
    of passive sources (certificate transparency, WHOIS, scraping, ...) often
    surfaces names subfinder's sources miss. Deliberately invoked in `-passive`
    mode only -- amass's active mode (brute force, zone transfers, port/web
    probing) is a materially different, more intrusive safety profile and is
    out of scope for this runner."""

    name = "amass"
    version = "4.2.0"
    binary = "amass"
    requires_active_testing = False  # passive-only invocation: public sources, no packets to the target
    capability = "subdomain_discovery"
    phase = 11  # alternate/complementary source alongside subfinder (10), both feed dnsx (15)
    kill_chain_phase = "reconnaissance"
    safety_tier = "passive"
    applicable_target_types = {"domain"}

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        timeout_seconds = config.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)

        # NO `-noalts`: that flag is Amass v3 and was REMOVED in v4, where altered-name
        # generation became opt-in via `-alts` instead. Passing it made v4.2.0 exit 1
        # immediately with "flag provided but not defined: -noalts" -- so amass had been
        # hard-failing on every single scan, contributing nothing, while looking like a
        # tool that simply found no subdomains. Omitting it keeps the original intent
        # (no name alterations) because v4 does not generate them unless asked.
        # Caught by `python -m apps.api.scanner_engine.doctor`, which now covers amass.
        command = ["amass", "enum", "-passive", "-d", target_value, "-norecursive"]

        # Give amass its OWN deadline, inside our wall-clock one. Passive enumeration
        # queries many external sources and routinely outlives the budget; without this
        # it gets SIGKILLed by the timeout branch below and every name it had already
        # collected is discarded with it. `-timeout` (whole minutes) makes amass stop
        # and PRINT what it has, exiting 0. The 0.8 factor leaves margin for it to wind
        # down and flush before our own kill would land.
        amass_minutes = max(1, int(timeout_seconds * 0.8) // 60)
        command += ["-timeout", str(amass_minutes)]

        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        # Incremental capture: a timeout now KEEPS whatever amass already collected
        # instead of discarding it (see base.run_with_timeout). amass's own `-timeout`
        # above is still the first line of defense; this is the backstop if that does
        # not land in time.
        result = await run_with_timeout(proc, timeout_seconds, "amass")
        if result.timed_out:
            return RawToolOutput(
                command=" ".join(command),
                stdout=result.stdout,
                stderr=(result.stderr + "\ntimed out").strip(),
                exit_code=-1,
                timed_out=True,
            )

        return RawToolOutput(
            command=" ".join(command),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=result.exit_code if result.exit_code is not None else -1,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        # Plain enum output (no -json): one discovered name per line.
        findings: list[CommonFinding] = []
        seen: set[str] = set()
        for line in raw.stdout.splitlines():
            host = line.strip().lower()
            if not host or " " in host or host in seen:
                continue
            seen.add(host)
            findings.append(CommonFinding(asset_type="subdomain", value=host, metadata={"source": "amass"}))
        return findings
