"""Scan doctor -- a real-execution self-test for the scanner tool binaries.

The unit tests only exercise each runner's `parse()` with fake output; nothing
verifies the actual binaries (nmap/naabu/subfinder/httpx/nuclei) run and produce
parseable results. This module does, by running each tool against a small, SAFE,
sanctioned target and asserting a usable result.

`scanme.nmap.org` is the target the Nmap project explicitly authorizes for scan
testing; we reuse it (and its HTTP service) for the network tools. Override via
env: SCAN_DOCTOR_DOMAIN / SCAN_DOCTOR_HTTP_HOST.

Usage (inside the worker image, which has the binaries + network):
    python -m apps.api.scanner_engine.doctor
Exit code is 0 only if every tool passes, so it doubles as a CI/liveness gate.
It is also imported by an opt-in `integration`-marked test.
"""
import asyncio
import os
from dataclasses import dataclass

from apps.api.scanner_engine.tool_runners.base import BaseToolRunner
from apps.api.scanner_engine.tool_runners.httpx_runner import HttpxRunner
from apps.api.scanner_engine.tool_runners.naabu_runner import NaabuRunner
from apps.api.scanner_engine.tool_runners.nmap_runner import NmapRunner
from apps.api.scanner_engine.tool_runners.nuclei_runner import NucleiRunner
from apps.api.scanner_engine.tool_runners.subfinder_runner import SubfinderRunner

SAFE_DOMAIN = os.environ.get("SCAN_DOCTOR_DOMAIN", "scanme.nmap.org")
SAFE_HTTP_HOST = os.environ.get("SCAN_DOCTOR_HTTP_HOST", "scanme.nmap.org")


@dataclass
class DoctorResult:
    tool: str
    ok: bool
    detail: str


async def _check(runner: BaseToolRunner, target: str, config: dict) -> DoctorResult:
    """A tool passes if it ran without raising AND either exited cleanly or
    produced parseable/any output -- i.e. it is installed, reachable, and its
    output shape still parses. (A benign 'no results' is a pass; a crash or a
    dead binary is a fail.)"""
    try:
        raw = await runner.run(target, config, [])
    except Exception as exc:  # noqa: BLE001
        return DoctorResult(runner.name, False, f"run() raised: {type(exc).__name__}: {exc}")
    try:
        assets = len(runner.parse(raw))
        vulns = len(runner.parse_vulnerabilities(raw))
    except Exception as exc:  # noqa: BLE001
        return DoctorResult(runner.name, False, f"parse() raised: {type(exc).__name__}: {exc}")
    ok = raw.exit_code == 0 or bool(assets or vulns or raw.stdout.strip())
    stderr_tail = (raw.stderr or "").strip()[-160:]
    return DoctorResult(
        runner.name, ok,
        f"exit={raw.exit_code} assets={assets} vulns={vulns}" + (f" stderr={stderr_tail!r}" if stderr_tail else ""),
    )


async def run_doctor() -> list[DoctorResult]:
    """Run every tool against the safe target. Nuclei uses a light tag set + short
    timeout so the check stays fast; the goal is 'does it run', not coverage."""
    checks = [
        (SubfinderRunner(), SAFE_DOMAIN, {"timeout_seconds": 60}),
        (HttpxRunner(), SAFE_HTTP_HOST, {"timeout_seconds": 60}),
        (NaabuRunner(), SAFE_DOMAIN, {"timeout_seconds": 90, "top_ports": 100}),
        # nmap standalone does -sV version detection; keep the doctor's port set
        # small so the check verifies "runs + parses" quickly and reliably. In a
        # real scan nmap only re-scans naabu's discovered ports, which is faster.
        (NmapRunner(), SAFE_DOMAIN, {"timeout_seconds": 200, "top_ports": 20}),
        (NucleiRunner(), SAFE_HTTP_HOST, {"timeout_seconds": 90, "nuclei_tags": "tech"}),
    ]
    return [await _check(runner, target, config) for runner, target, config in checks]


def main() -> int:
    results = asyncio.run(run_doctor())
    print(f"Scan doctor (target: {SAFE_DOMAIN})\n" + "-" * 60)
    for r in results:
        print(f"  [{'PASS' if r.ok else 'FAIL'}] {r.tool:<10} {r.detail}")
    failed = [r.tool for r in results if not r.ok]
    if failed:
        print(f"\nFAILED: {', '.join(failed)}")
        return 1
    print("\nAll tools OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
