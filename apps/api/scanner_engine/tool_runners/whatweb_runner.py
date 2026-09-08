import asyncio
import json
import logging

from apps.api.scanner_engine.tool_runners._web import web_targets
from apps.api.scanner_engine.tool_runners.base import (
    BaseToolRunner,
    CommonFinding,
    RawToolOutput,
    run_with_timeout,
)

logger = logging.getLogger("mbs.scanner.whatweb")

# --- Timeout policy -----------------------------------------------------------------------
# The old fixed 120s was BELOW whatweb's real runtime for the command this runner actually
# issues. Measured against a live authorized target (www.lincoln.edu.my, one target, -a 3):
# 152s to exit 0 with a full fingerprint. The 120s ceiling killed it 32s short and returned
# nothing -- a tool that works, reported as a failure.
#
# The budget is now DERIVED from what drives the runtime rather than being a constant:
#   budget = BASE_PER_TARGET_SECONDS * targets * aggression_factor
# clamped to [MIN, MAX]. `-a 3` is whatweb's aggressive mode: it issues far more requests per
# target than the default, which is exactly why the old constant did not fit.
#
# This is deliberately NOT a global timeout change -- it applies to whatweb only, and an
# explicit tool_config `timeout_seconds` still overrides it.
BASE_PER_TARGET_SECONDS = 100
AGGRESSION_FACTOR = {1: 1.0, 2: 1.6, 3: 3.0, 4: 4.0}
MIN_TIMEOUT_SECONDS = 120
MAX_TIMEOUT_SECONDS = 1800
DEFAULT_AGGRESSION = 3

# Retained so an explicit config value keeps its historical meaning; no longer the default.
DEFAULT_TIMEOUT_SECONDS = 120


def compute_timeout(target_count: int, aggression: int = DEFAULT_AGGRESSION) -> int:
    """Wall-clock budget for one whatweb invocation. Pure, so it is unit-testable.

    Scales with the number of targets (they share ONE invocation and therefore one budget)
    and with aggression (higher `-a` = more probes per target). Clamped at both ends so a
    huge target list cannot produce an effectively unbounded run."""
    factor = AGGRESSION_FACTOR.get(aggression, AGGRESSION_FACTOR[DEFAULT_AGGRESSION])
    budget = BASE_PER_TARGET_SECONDS * max(1, target_count) * factor
    return int(max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, budget)))


class WhatwebRunner(BaseToolRunner):
    """Web technology fingerprinting (WhatWeb). A second, independent
    implementation of `web_service_discovery` alongside httpx: WhatWeb's
    plugin-based signature set (CMS, framework, JS library, server-software
    fingerprints) is broader in places than httpx's built-in -tech-detect, so it
    re-probes the same live hosts httpx confirmed for a richer fingerprint.
    Re-upserts the same `http_service` asset with its own tech metadata rather
    than inventing a new asset type."""

    name = "whatweb"
    version = "0.5.5"
    binary = "whatweb"
    requires_active_testing = False  # benign HTTP GET probing -- passive recon, like httpx
    capability = "web_service_discovery"
    phase = 22  # right after httpx (20): fingerprints the same live hosts more deeply
    kill_chain_phase = "reconnaissance"
    safety_tier = "active_safe"  # sends benign HTTP probes (no state change)

    async def run(self, target_value: str, config: dict, prior_findings: list[CommonFinding]) -> RawToolOutput:
        targets = web_targets(target_value, prior_findings)
        if not targets:
            return RawToolOutput(command="whatweb (no web targets)", stdout="", stderr="no web targets", exit_code=-1)

        aggression = int(config.get("whatweb_aggression", DEFAULT_AGGRESSION))
        command = ["whatweb", "--log-json=-", "--no-errors", "-a", str(aggression), *targets]

        # An explicit tool_config value always wins; otherwise the budget is derived from the
        # workload (see compute_timeout) instead of a constant that did not fit the command.
        timeout = config.get("timeout_seconds") or compute_timeout(len(targets), aggression)
        logger.info(
            "whatweb.start targets=%d aggression=%d timeout=%ss",
            len(targets), aggression, timeout,
        )

        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        # Incremental capture: a timeout now KEEPS whatever whatweb already fingerprinted
        # instead of discarding it (see base.run_with_timeout).
        result = await run_with_timeout(proc, timeout, "whatweb")
        if result.timed_out:
            # NOT reported as success. Partial stdout (if any) is preserved and the non-zero
            # exit lets classify_run mark the run `partial` rather than `completed`.
            note = f"timed out after {timeout}s"
            logger.warning(
                "whatweb.timeout targets=%d after=%ss stdout_bytes=%d",
                len(targets), timeout, len(result.stdout),
            )
            return RawToolOutput(
                command=" ".join(command),
                stdout=result.stdout,
                stderr=(result.stderr + "\n" + note).strip(),
                exit_code=-1,
            )

        return RawToolOutput(
            command=" ".join(command),
            stdout=result.stdout,
            stderr=result.stderr,
            exit_code=proc.returncode if proc.returncode is not None else -1,
        )

    def parse(self, raw: RawToolOutput) -> list[CommonFinding]:
        findings: list[CommonFinding] = []
        for line in raw.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            target = obj.get("target")
            if not target:
                continue
            plugins = obj.get("plugins") or {}
            findings.append(
                CommonFinding(
                    asset_type="http_service",
                    value=target,
                    metadata={
                        "source": "whatweb",
                        "status_code": obj.get("http_status"),
                        "tech": sorted(plugins.keys()),
                    },
                )
            )
        return findings
