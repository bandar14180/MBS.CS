"use client";

import { useCallback, useEffect, useState } from "react";

import { scanApi, type Scan, type ToolRun } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Spinner } from "@/components/ui";

// Each stage: a translated descriptor + the tool's proper name (kept LTR).
const STAGES: Record<string, { key: string; tool: string }> = {
  subfinder: { key: "scans.stageSubfinder", tool: "Subfinder" },
  httpx: { key: "scans.stageHttpx", tool: "Httpx" },
  naabu: { key: "scans.stageNaabu", tool: "Naabu" },
  nmap: { key: "scans.stageNmap", tool: "Nmap" },
  nuclei: { key: "scans.stageNuclei", tool: "Nuclei" },
};
const PHASE_ORDER = ["subfinder", "httpx", "naabu", "nmap", "nuclei"];
const TERMINAL = new Set(["completed", "failed", "completed_with_errors", "cancelled"]);

type StageState = "waiting" | "running" | "completed" | "failed" | "skipped";

function scanDuration(scan: Scan): string | null {
  if (!scan.started_at || !scan.completed_at) return null;
  const s = (new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000;
  return s >= 60 ? `${Math.floor(s / 60)}m ${Math.round(s % 60)}s` : `${s.toFixed(1)}s`;
}

function suggestFixKey(error: string | null): string {
  const e = (error || "").toLowerCase();
  if (e.includes("resolvable") || e.includes("dns resolution") || e.includes("name or service not known"))
    return "scans.fixDns";
  if (e.includes("timed out") || e.includes("timeout")) return "scans.fixTimeout";
  if (e.includes("connection refused") || e.includes("no route")) return "scans.fixRefused";
  return "scans.fixGeneric";
}

// Technical/English text (tool names, commands, errors) must render LTR so
// bidirectional punctuation doesn't flip inside an RTL page.
function Ltr({ children }: { children: React.ReactNode }) {
  return (
    <span dir="ltr" className="inline-block">
      {children}
    </span>
  );
}

export function ScanProgress({ projectId, scan }: { projectId: string; scan: Scan }) {
  const { t } = useTranslation();
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

  function stateFor(tool: string): { state: StageState; run?: ToolRun } {
    const run = runByTool.get(tool);
    if (run) {
      if (run.status === "completed") return { state: "completed", run };
      if (run.status === "running") return { state: "running", run };
      if (run.status === "skipped_unauthorized") return { state: "skipped", run };
      return { state: "failed", run };
    }
    return { state: live ? "waiting" : "skipped" };
  }

  const total = scanDuration(scan);
  const failedRun = scan.status === "failed" ? (runs || []).find((r) => r.status === "failed") : undefined;

  return (
    <div className="mt-4 border-t border-cyber-border/60 pt-4">
      {failedRun && (
        <div className="mb-4 rounded-xl border border-rose-500/40 bg-rose-500/10 p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-rose-300">
            <span className="text-base">✕</span> {t("scans.scanFailed")}
          </div>
          <dl className="mt-2 space-y-1 text-sm">
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-slate-400">{t("scans.tool")}</dt>
              <dd className="text-slate-200">
                {t(STAGES[failedRun.tool_name]?.key || failedRun.tool_name)}{" "}
                <Ltr>({STAGES[failedRun.tool_name]?.tool || failedRun.tool_name})</Ltr>
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-slate-400">{t("scans.reason")}</dt>
              <dd className="font-mono text-rose-300">
                <Ltr>{failedRun.error_message || "unknown error"}</Ltr>
              </dd>
            </div>
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-slate-400">{t("scans.suggestedFix")}</dt>
              <dd className="text-slate-300">{t(suggestFixKey(failedRun.error_message))}</dd>
            </div>
          </dl>
          <p className="mt-3 text-xs text-slate-400">{t("scans.pipelineStopped")}</p>
        </div>
      )}

      {runs === null ? (
        <Spinner />
      ) : (
        <ol className="space-y-2">
          {stages.map((tool) => {
            const { state, run } = stateFor(tool);
            return <StageRow key={tool} tool={tool} state={state} run={run} />;
          })}
        </ol>
      )}

      <div className="mt-3 flex items-center justify-between text-xs">
        <span className="text-slate-500">
          {live ? t("scans.live") : scan.status === "failed" ? t("scans.scanFailedShort") : ""}
        </span>
        {total && (
          <span className="font-medium text-slate-300">
            {t("scans.total")}: <Ltr>{total}</Ltr>
          </span>
        )}
      </div>
    </div>
  );
}

function StageRow({ tool, state, run }: { tool: string; state: StageState; run?: ToolRun }) {
  const { t } = useTranslation();
  const stage = STAGES[tool] || { key: tool, tool };
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
  const dur = run?.duration_seconds != null ? ` (${run.duration_seconds}s)` : "";
  const statusText: Record<StageState, string> = {
    completed: t("scans.sCompleted") + dur,
    running: t("scans.sRunning"),
    failed: t("scans.sFailed") + dur,
    waiting: t("scans.sWaiting"),
    skipped: t("scans.sSkipped"),
  };
  const statusColor =
    state === "completed" ? "text-emerald-400"
    : state === "running" ? "text-sky-400"
    : state === "failed" ? "text-rose-400"
    : "text-slate-500";

  return (
    <li className="rounded-lg border border-cyber-border/50 bg-white/[0.02] px-3 py-2.5">
      <div className="flex items-center gap-3">
        <span className="flex h-5 w-5 items-center justify-center text-sm">{icon[state]}</span>
        <span className={`flex-1 text-sm font-medium ${labelColor}`}>
          {t(stage.key)} <Ltr>({stage.tool})</Ltr>
        </span>
        <span className={`text-xs ${statusColor}`}>
          <Ltr>{statusText[state]}</Ltr>
        </span>
      </div>
      {state === "failed" && run?.error_message && (
        <div className="ms-8 mt-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 font-mono text-xs text-rose-300">
          <Ltr>{run.error_message}</Ltr>
        </div>
      )}
    </li>
  );
}
