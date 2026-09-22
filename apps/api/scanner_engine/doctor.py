"""Scan doctor -- a real-execution self-test for the scanner tool binaries.

The unit tests only exercise each runner's `parse()` with fake output; nothing
verifies the actual binaries run and produce parseable results. This module does,
by running EVERY registered tool against a small, SAFE, sanctioned target and
asserting a usable result.

`scanme.nmap.org` is the target the Nmap project explicitly authorizes for scan
testing; we reuse it (and its HTTP service) for the network tools. Override via
env: SCAN_DOCTOR_DOMAIN / SCAN_DOCTOR_HTTP_HOST.

Two passes, because they answer different questions:

  1. PREFLIGHT  -- is each tool's binary on PATH, and are its non-binary
     prerequisites (nuclei's template dir, ffuf's wordlist) present? Milliseconds,
     no network. This is what distinguishes "found nothing" from "never installed".
  2. EXECUTION  -- does the binary actually run against a live target and does its
     output still parse? Minutes, needs egress.

Coverage is derived from TOOL_REGISTRY, not a hand-maintained list: a registered
tool with no check FAILS the run rather than being silently skipped (previously
ffuf/arjun/katana/nuclei-dast/amass/whatweb/dnsx were uncovered here, and four of
them were also invisible in the UI -- so a broken install had no surface at all).

T3 boundary note: like before, every doctor execution passes an EMPTY prior-findings
list -- the doctor never probes assets derived from a real scan. Tools that only
have work to do when an earlier phase fed them something (arjun needs crawled
endpoints) therefore report SKIP here; their installation is covered by the
preflight pass instead. See tests/test_runner_boundary.py.

Usage (inside the worker image, which has the binaries + network):
    python -m apps.api.scanner_engine.doctor                    # preflight + execution
    python -m apps.api.scanner_engine.doctor --preflight-only   # PATH/config check only
Exit code is 0 only if every tool passes, so it doubles as a CI/liveness gate.
It is also imported by an opt-in `integration`-marked test.
"""
import asyncio
import functools
import os
import sys
import tempfile
from dataclasses import dataclass

from apps.api.scanner_engine.tool_registry import TOOL_REGISTRY
from apps.api.scanner_engine.tool_runners.base import BaseToolRunner, RawToolOutput

SAFE_DOMAIN = os.environ.get("SCAN_DOCTOR_DOMAIN", "scanme.nmap.org")
SAFE_HTTP_HOST = os.environ.get("SCAN_DOCTOR_HTTP_HOST", "scanme.nmap.org")


@dataclass
class DoctorResult:
    tool: str
    ok: bool
    detail: str
    # A tool that had nothing to do standalone (needs an earlier phase's output).
    # Not a failure -- but never silently reported as a clean PASS either.
    skipped: bool = False

    @property
    def label(self) -> str:
        return "SKIP" if self.skipped else ("PASS" if self.ok else "FAIL")


def _short_circuited(raw: RawToolOutput) -> bool:
    """True when a runner returned without ever launching its binary.

    The runners signal this in their synthesized `command` string -- e.g.
    "arjun (no endpoints to probe)", "ffuf (no web targets)",
    "nuclei -dast (no targets)". Without this check such a run looks like a clean
    exit-0 pass, which would let a completely missing binary slip through the
    execution pass unnoticed."""
    return " (no " in raw.command


async def _check(runner: BaseToolRunner, target: str, config: dict) -> DoctorResult:
    """A tool passes if it ran without raising AND either exited cleanly or
    produced parseable/any output -- i.e. it is installed, reachable, and its
    output shape still parses. (A benign 'no results' is a pass; a crash or a
    dead binary is a fail.)"""
    try:
        raw = await runner.run(target, config, [])
    except FileNotFoundError as exc:
        # The single most common real-world failure: the binary isn't installed in
        # this process's PATH. Name it explicitly rather than leaving a bare OSError.
        return DoctorResult(
            runner.name, False, f"binary {runner.binary or runner.name!r} not found on PATH ({exc})"
        )
    except Exception as exc:  # noqa: BLE001
        return DoctorResult(runner.name, False, f"run() raised: {type(exc).__name__}: {exc}")

    if _short_circuited(raw):
        reason = (raw.stderr or "").strip() or raw.command
        return DoctorResult(
            runner.name, True, f"binary never launched standalone ({reason}) -- see preflight", skipped=True
        )

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


@functools.lru_cache(maxsize=1)
def _tiny_wordlist() -> str:
    """A handful of paths, written once to a temp file, for the ffuf check.

    Content discovery is request-heavy by nature; the doctor only needs enough requests
    to prove the binary executes and its `-json` output still parses. Cached so repeated
    _checks() calls (uncovered_tools() calls it too) reuse the same file."""
    fd, path = tempfile.mkstemp(prefix="scan-doctor-ffuf-", suffix=".txt", text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(["", "index.html", "robots.txt", "admin", "login", ".git", "images"]) + "\n")
    return path


def _checks() -> list[tuple[BaseToolRunner, str, dict]]:
    """One check per registered tool. Timeouts/args are tuned so the whole run
    stays under a couple of minutes: the question is 'does it execute and parse',
    not 'how much can it find'."""
    return [
        (TOOL_REGISTRY["subfinder"](), SAFE_DOMAIN, {"timeout_seconds": 60}),
        # Passive amass queries many external sources and needs minutes, not seconds;
        # 200s also gives its own `-timeout` derivation (0.8x, whole minutes) a real
        # 2-minute budget with margin to wind down and print what it found.
        (TOOL_REGISTRY["amass"](), SAFE_DOMAIN, {"timeout_seconds": 200}),
        (TOOL_REGISTRY["dnsx"](), SAFE_DOMAIN, {"timeout_seconds": 60}),
        (TOOL_REGISTRY["httpx"](), SAFE_HTTP_HOST, {"timeout_seconds": 60}),
        (TOOL_REGISTRY["whatweb"](), SAFE_HTTP_HOST, {"timeout_seconds": 60}),
        (TOOL_REGISTRY["naabu"](), SAFE_DOMAIN, {"timeout_seconds": 90, "top_ports": 100}),
        # nmap standalone does -sV version detection; keep the doctor's port set
        # small so the check verifies "runs + parses" quickly and reliably. In a
        # real scan nmap only re-scans naabu's discovered ports, which is faster.
        (TOOL_REGISTRY["nmap"](), SAFE_DOMAIN, {"timeout_seconds": 200, "top_ports": 20}),
        # No prior findings -> _web.web_targets falls back to http(s) on the bare
        # host, so katana/ffuf/nuclei-dast all still exercise their real binary.
        (TOOL_REGISTRY["katana"](), SAFE_HTTP_HOST, {"timeout_seconds": 90, "crawl_depth": 1}),
        # ffuf runs against a TINY wordlist here, not the configured one. The real
        # default (dirb's common.txt, ~4.6k entries) means ~4.6k requests per scheme,
        # which scanme.nmap.org -- a courtesy host the Nmap project asks people not to
        # hammer -- rate-limits into a guaranteed timeout. That measures the target's
        # patience, not ffuf. Whether FFUF_WORDLIST_PATH is actually configured is
        # already a hard PREFLIGHT check, so the split is clean: preflight covers the
        # configuration, this covers "the binary runs and its JSON output still parses".
        (TOOL_REGISTRY["ffuf"](), SAFE_HTTP_HOST, {"timeout_seconds": 90, "ffuf_wordlist_path": _tiny_wordlist()}),
        # arjun only probes endpoints an earlier phase crawled; standalone it is a
        # SKIP by design (preflight covers whether the CLI is installed).
        (TOOL_REGISTRY["arjun"](), SAFE_HTTP_HOST, {"timeout_seconds": 120}),
        (TOOL_REGISTRY["nuclei"](), SAFE_HTTP_HOST, {"timeout_seconds": 90, "nuclei_tags": "tech"}),
        # -dast against a paramless target finds nothing; the check is that the
        # binary accepts -dast and the JSONL parser still handles empty output.
        (TOOL_REGISTRY["nuclei-dast"](), SAFE_HTTP_HOST, {"timeout_seconds": 90}),
    ]


def uncovered_tools() -> list[str]:
    """Registered tools with no doctor check -- a coverage gap, reported as a failure."""
    covered = {runner.name for runner, _, _ in _checks()}
    return sorted(set(TOOL_REGISTRY) - covered)


def run_preflight() -> list[DoctorResult]:
    """PATH/prerequisite resolution only -- no network, no subprocess. Answers
    'which tools CAN run here' in milliseconds; the execution pass answers 'do they
    actually work'."""
    from apps.api.scanner_engine.tool_preflight import preflight

    results: list[DoctorResult] = []
    for s in preflight():
        if not s.available:
            results.append(DoctorResult(s.tool, False, f"binary {s.binary!r} NOT on PATH"))
        elif s.missing_requirements:
            results.append(DoctorResult(s.tool, False, f"{s.path} -- {'; '.join(s.missing_requirements)}"))
        else:
            results.append(DoctorResult(s.tool, True, str(s.path)))
    return results


async def run_doctor() -> list[DoctorResult]:
    """Run every registered tool against the safe target."""
    results = [await _check(runner, target, config) for runner, target, config in _checks()]
    results.extend(
        DoctorResult(name, False, "no doctor check registered for this tool (coverage gap)")
        for name in uncovered_tools()
    )
    return results


def _report(title: str, results: list[DoctorResult]) -> list[str]:
    print(f"\n{title}\n" + "-" * 72)
    for r in results:
        print(f"  [{r.label}] {r.tool:<12} {r.detail}")
    return [r.tool for r in results if not r.ok]


def main() -> int:
    preflight_only = "--preflight-only" in sys.argv
    print(f"Scan doctor (target: {SAFE_DOMAIN}, {len(TOOL_REGISTRY)} registered tools)")

    missing = _report("Preflight -- binaries on PATH + runtime prerequisites", run_preflight())
    if preflight_only:
        if missing:
            print(f"\nFAILED (preflight): {', '.join(missing)}")
            return 1
        print("\nAll tool binaries present and configured.")
        return 0

    failed = _report("Execution -- real run against the safe target", asyncio.run(run_doctor()))
    if missing or failed:
        if missing:
            print(f"\nFAILED (preflight): {', '.join(missing)}")
        if failed:
            print(f"FAILED (execution): {', '.join(failed)}")
        return 1
    print("\nAll tools OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
