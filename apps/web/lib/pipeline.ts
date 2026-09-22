"use client";

// Single source of truth, on the client, for "which scanner tools exist and in what
// order". Everything that renders a tool list -- the scan form, the schedule form,
// the scan-progress widget -- reads it from here.
//
// Why this module exists: each of those three components used to carry its own
// hardcoded tool array. They had drifted apart AND away from the backend's
// TOOL_REGISTRY: `amass`, `dnsx`, `whatweb` and `ffuf` were registered, installed and
// runnable server-side but appeared in none of them, so they could never be selected
// for a scan, and on the rare path that did request them (API, schedule, AI planner)
// the progress widget filtered their ToolRun rows out -- hiding successes and
// failures alike. SchedulesPanel was narrower still (5 of 12).
//
// The list now comes from GET /scan-capabilities/pipeline, derived from TOOL_REGISTRY.
// FALLBACK_PIPELINE below is only for the pre-fetch render and for an API that isn't
// reachable yet; apps/api/tests/test_frontend_pipeline_sync.py fails the build if it
// stops matching the backend registry, so the drift cannot silently return.
import { useEffect, useState } from "react";

import { scanApi, type PipelineTool } from "@/lib/api";

// Mirrors apps/api/scanner_engine/tool_registry.py (each runner's `phase`).
// Kept in sync by apps/api/tests/test_frontend_pipeline_sync.py.
export const FALLBACK_PIPELINE: PipelineTool[] = [
  f("subfinder", 10, "subdomain_discovery", "discovery", false, ["domain"]),
  f("amass", 11, "subdomain_discovery", "discovery", false, ["domain"]),
  f("dnsx", 15, "subdomain_discovery", "discovery", false, ["domain"]),
  f("httpx", 20, "web_service_discovery", "web", false, null),
  f("whatweb", 22, "web_service_discovery", "web", false, null),
  f("naabu", 30, "port_discovery", "network", false, null),
  f("nmap", 40, "service_fingerprinting", "network", false, null),
  f("katana", 45, "web_crawling", "web", false, ["domain", "ip_range"]),
  f("ffuf", 46, "content_discovery", "web", true, ["domain", "ip_range"]),
  f("arjun", 48, "parameter_discovery", "web", true, ["domain", "ip_range"]),
  f("nuclei", 50, "vulnerability_detection", "web", true, null, true),
  f("nuclei-dast", 55, "dast_fuzzing", "web", true, null, true),
];

function f(
  name: string,
  phase: number,
  capability: string,
  category: string,
  requires_active_testing: boolean,
  applicable_target_types: string[] | null,
  produces_vulnerabilities = false
): PipelineTool {
  return {
    name,
    phase,
    capability,
    category,
    kill_chain_phase: produces_vulnerabilities ? "delivery" : "reconnaissance",
    safety_tier: "active_safe",
    requires_active_testing,
    applicable_target_types,
    produces_vulnerabilities,
    binary: name,
    // Unknown until the API answers back with the worker's reported view. null (not
    // false) so the fallback never greys out a tool that is in fact installed.
    binary_available: null,
    missing_requirements: [],
  };
}

// The pipeline is global and immutable for the life of a deployment, so one fetch per
// page load is plenty; this caches it across every component that asks.
let cached: PipelineTool[] | null = null;
let inflight: Promise<PipelineTool[]> | null = null;

export async function loadPipeline(): Promise<PipelineTool[]> {
  if (cached) return cached;
  if (!inflight) {
    inflight = scanApi
      .pipeline()
      .then((tools) => {
        cached = tools.length ? [...tools].sort((a, b) => a.phase - b.phase) : FALLBACK_PIPELINE;
        return cached;
      })
      .catch(() => FALLBACK_PIPELINE)
      .finally(() => {
        inflight = null;
      });
  }
  return inflight;
}

/** The registered tools in execution order. Starts on the static fallback so the first
 *  paint already shows the full pipeline, then swaps in the authoritative list. */
export function usePipeline(): PipelineTool[] {
  const [tools, setTools] = useState<PipelineTool[]>(cached ?? FALLBACK_PIPELINE);
  useEffect(() => {
    let alive = true;
    loadPipeline().then((t) => {
      if (alive) setTools(t);
    });
    return () => {
      alive = false;
    };
  }, []);
  return tools;
}

/** Tool names in execution order. */
export function pipelineOrder(tools: PipelineTool[]): string[] {
  return tools.map((t) => t.name);
}

/** Order a caller's tool names by pipeline phase, keeping any name the pipeline
 *  doesn't know (a tool added server-side, or a run from an older scan) at the end
 *  rather than dropping it -- silently dropping is the bug this module fixes. */
export function sortByPhase(names: string[], tools: PipelineTool[]): string[] {
  const phase = new Map(tools.map((t) => [t.name, t.phase]));
  return [...names].sort((a, b) => {
    const pa = phase.get(a) ?? Number.MAX_SAFE_INTEGER;
    const pb = phase.get(b) ?? Number.MAX_SAFE_INTEGER;
    return pa === pb ? a.localeCompare(b) : pa - pb;
  });
}
