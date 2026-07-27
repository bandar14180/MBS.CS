"use client";

import { useCallback, useEffect, useState } from "react";

import { scanApi, type Scan, type ToolRun } from "@/lib/api";
import { Spinner } from "@/components/ui";

// Human labels for each pipeline stage, in phase order.
const STAGE_LABEL: Record<string, string> = {
  subfinder: "Recon — Subdomains (Subfinder)",
  httpx: "Live Hosts (Httpx)",
  naabu: "Port Scan (Naabu)",
  nmap: "Service Detection (Nmap)",
  nuclei: "Vulnerability Scan (Nuclei)",
};
const PHASE_ORDER = ["subfinder", "httpx", "naabu", "nmap", "nuclei"];
const TERMINAL = new Set(["completed", "failed", "completed_with_errors", "cancelled"]);

type StageState = "waiting" | "running" | "completed" | "failed" | "skipped";

function scanDuration(scan: Scan): string | null {
  if (!scan.started_at || !scan.completed_at) return null;
  const s = (new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000;
  return s >= 60 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${s.toFixed(1)}s`;
}

export function ScanProgress({ projectId, scan }: { projectId: string; scan: Scan }) {
  const [runs, setRuns] = useState<ToolRun[] | null>(null);
  const live = !TERMINAL.has(scan.status);

  const load = useCallback(async () => {
    try {
      setRuns(await scanApi.toolRuns(projectId, scan.id));
    } catch {}
  }, [projectId, scan.id]);

  useEffect(() => {
    load();
    if (!live) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load, live]);

  const requested: string[] = scan.config?.requested_modules || [];
  const stages = PHASE_ORDER.filter((m) => requested.includes(m));
  const runByTool = new Map((runs || []).map((r) => [r.tool_name, r]));

  // Derive each stage's display state from its tool-run (if any) + scan state.
  function stateFor(tool: string): { state: StageState; run?: ToolRun } {
    const run = runByTool.get(tool);
    if (run) {
      if (run.status === "completed") return { state: "completed", run };
      if (run.status === "running") return { state: "running", run };
      if (run.status === "skipped_unauthorized") return { state: "skipped", run };
      return { state: "failed", run }; // failed / anything else terminal-bad
    }
    // No run row yet: waiting if the scan is still active, otherwise it was skipped.
    return { state: live ? "waiting" : "skipped" };
  }

  const total = scanDuration(scan);

  return (
    <div className="mt-4 border-t border-cyber-border/60 pt-4">
      {runs === null ? (
        <Spinner />
      ) : (
        <ol className="space-y-2">
          {stages.map((tool) => {
            const { state, run } = stateFor(tool);
            return <StageRow key={tool} label={STAGE_LABEL[tool] || tool} state={state} run={run} />;
          })}
        </ol>
      )}
      <div className="mt-3 flex items-center justify-between text-xs">
        <span className="text-slate-500">
          {live ? "Live — polling every 3s" : `Scan ${scan.status.replace(/_/g, " ")}`}
        </span>
        {total && <span className="font-medium text-slate-300">Total: {total}</span>}
      </div>
    </div>
  );
}

function StageRow({ label, state, run }: { label: string; state: StageState; run?: ToolRun }) {
  const icon: Record<StageState, React.ReactNode> = {
    completed: <span className="text-emerald-400">✓</span>,
    running: <Spinner />,
    failed: <span className="text-rose-400">✕</span>,
    waiting: <span className="text-slate-600">○</span>,
    skipped: <span className="text-slate-600">—</span>,
  };
  const labelColor =
    state === "completed" ? "text-slate-100"
    : state === "running" ? "text-sky-300"
    : state === "failed" ? "text-rose-300"
    : "text-slate-500";
  const statusText: Record<StageState, string> = {
    completed: run?.duration_seconds != null ? `Completed (${run.duration_seconds}s)` : "Completed",
    running: "Running…",
    failed: run?.duration_seconds != null ? `Failed (${run.duration_seconds}s)` : "Failed",
    waiting: "Waiting",
    skipped: "Skipped",
  };

  return (
    <li className="rounded-lg border border-cyber-border/50 bg-white/[0.02] px-3 py-2.5">
      <div className="flex items-center gap-3">
        <span className="flex h-5 w-5 items-center justify-center text-sm">{icon[state]}</span>
        <span className={`flex-1 text-sm font-medium ${labelColor}`}>{label}</span>
        <span
          className={`text-xs ${
            state === "completed" ? "text-emerald-400"
            : state === "running" ? "text-sky-400"
            : state === "failed" ? "text-rose-400"
            : "text-slate-500"
          }`}
        >
          {statusText[state]}
        </span>
      </div>
      {state === "failed" && run?.error_message && (
        <div className="ms-8 mt-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 font-mono text-xs text-rose-300">
          {run.error_message}
        </div>
      )}
    </li>
  );
}
