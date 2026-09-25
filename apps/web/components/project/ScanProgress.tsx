"use client";

import { useCallback, useEffect, useState } from "react";

import { scanApi, type Scan, type ToolRun } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { usePipeline, sortByPhase } from "@/lib/pipeline";
import { Spinner } from "@/components/ui";

// Each stage: a translated descriptor + the tool's proper name (kept LTR). Pipeline
// ORDER comes from the backend (lib/pipeline.ts); this map only supplies display
// labels, and an unknown tool falls back to its raw name rather than disappearing.
const STAGES: Record<string, { key: string; tool: string }> = {
  subfinder: { key: "scans.stageSubfinder", tool: "Subfinder" },
  amass: { key: "scans.stageAmass", tool: "Amass" },
  dnsx: { key: "scans.stageDnsx", tool: "Dnsx" },
  httpx: { key: "scans.stageHttpx", tool: "Httpx" },
  whatweb: { key: "scans.stageWhatweb", tool: "WhatWeb" },
  naabu: { key: "scans.stageNaabu", tool: "Naabu" },
  nmap: { key: "scans.stageNmap", tool: "Nmap" },
  katana: { key: "scans.stageKatana", tool: "Katana" },
  ffuf: { key: "scans.stageFfuf", tool: "Ffuf" },
  arjun: { key: "scans.stageArjun", tool: "Arjun" },
  nuclei: { key: "scans.stageNuclei", tool: "Nuclei" },
  "nuclei-dast": { key: "scans.stageNucleiDast", tool: "Nuclei DAST" },
};
const TERMINAL = new Set(["completed", "failed", "completed_with_errors", "cancelled"]);

type StageState =
  | "waiting"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "skippedUnauth"
  | "notApplicable"
  | "notRun"
  | "cancelledStage";

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
  const pipeline = usePipeline();
  const [runs, setRuns] = useState<ToolRun[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const live = !TERMINAL.has(scan.status);

  // A failed poll must NOT discard the stage list. This used to be `catch {}`, which left
  // `runs` at null forever: the render below gated the whole <ol> on `runs === null`, so a
  // single failing tool-runs request (or one that had not answered yet) replaced every tool
  // row with a bare spinner -- the scan card then showed only the target, the comma-separated
  // module line and the "live" indicator, with no per-tool state at all, and swallowing the
  // error meant nothing said why. Keep the last good rows, surface the failure, and let the
  // 3s poll recover on its own.
  const load = useCallback(async () => {
    try {
      setRuns(await scanApi.toolRuns(projectId, scan.id));
      setLoadError(null);
    } catch (e: any) {
      setLoadError(e?.message || "unknown error");
    }
  }, [projectId, scan.id]);

  useEffect(() => {
    load();
    if (!live) return;
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load, live]);

  const requested: string[] = scan.config?.requested_modules || [];
  const runByTool = new Map((runs || []).map((r) => [r.tool_name, r]));
  // Union of what the scan asked for and what actually produced a ToolRun row, ordered
  // by pipeline phase. The union matters: this used to be a filter against a hardcoded
  // 8-tool list, so a ToolRun for amass/dnsx/whatweb/ffuf -- or for any tool a scan
  // requested through the API, a schedule or the AI planner rather than this UI -- was
  // fetched and then silently thrown away, hiding its result AND its failure. Nothing
  // the backend reports is dropped here any more.
  const stages = sortByPhase(
    Array.from(new Set([...requested, ...Array.from(runByTool.keys())])),
    pipeline
  );

  function stateFor(tool: string): { state: StageState; run?: ToolRun } {
    const run = runByTool.get(tool);
    if (run) {
      if (run.status === "completed") return { state: "completed", run };
      if (run.status === "running") return { state: "running", run };
      // `partial` is a real backend status (classify_run: a non-zero exit that STILL
      // yielded usable output, e.g. a katana crawl stopped by its per-target output
      // budget). It used to fall through to the `failed` catch-all below, which reported
      // a stage as failed while its findings were kept and ingested -- the one case the
      // union above did not cover. Amber, not red: coverage was bounded, not lost.
      if (run.status === "partial") return { state: "partial", run };
      if (run.status === "skipped_unauthorized") return { state: "skippedUnauth", run };
      return { state: "failed", run };
    }
    // No tool-run row: it's still pending (live), or the scan ended. A finished
    // "failed" scan means later stages didn't run; "cancelled" means the user stopped
    // it before this stage launched; a "completed" scan means the tool simply doesn't
    // apply to this target type (e.g. subfinder needs a domain).
    if (live) return { state: "waiting" };
    if (scan.status === "failed") return { state: "notRun" };
    if (scan.status === "cancelled") return { state: "cancelledStage" };
    return { state: "notApplicable" };
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

      {/* The tool-runs fetch is only needed to fill in per-tool STATE; the set of stages
          itself comes from scan.config.requested_modules, which is already on the scan row.
          So render the rows as soon as there is anything to show and fall back to the
          spinner only when there is genuinely nothing yet -- a pending or failing poll must
          never blank out the pipeline. stateFor() still reports "waiting" (live) or the
          appropriate did-not-run state for a tool with no ToolRun row, so nothing here
          invents a status the backend did not report. */}
      {loadError && (
        <div className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-xs text-amber-300">
          {t("scans.progressUnavailable")} <Ltr>{loadError}</Ltr>
        </div>
      )}

      {runs === null && stages.length === 0 ? (
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
          {live
            ? t("scans.live")
            : scan.status === "failed"
              ? t("scans.scanFailedShort")
              : scan.status === "cancelled"
                ? t("scans.scanCancelledShort")
                : ""}
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

// Seconds a still-running tool has been going, from its server-side started_at. Ticks
// on its own so the number moves between the 3s poll cycles.
function useLiveElapsed(run: ToolRun | undefined, running: boolean): number | null {
  const [, force] = useState(0);
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => force((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [running]);
  if (!running || !run?.started_at) return null;
  return Math.max(0, (Date.now() - new Date(run.started_at).getTime()) / 1000);
}

function fmtElapsed(s: number): string {
  return s >= 60 ? `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s` : `${Math.floor(s)}s`;
}

// Past this, a stage is called out as slow rather than just spinning. Tuned to the
// tools' own per-target timeouts (ffuf 180s/target, arjun 300s/target): under two
// minutes is normal for the crawl/fuzz phases, beyond it is worth explaining.
const SLOW_STAGE_SECONDS = 120;

// Why THIS tool is slow. The fan-out tools each probe many targets/endpoints and are
// slow for a reason the user can act on (narrow the wordlist, raise a timeout); the
// rest are just waiting on a slow target.
function slowHintKey(tool: string): string {
  if (tool === "ffuf") return "scans.slowFfuf";
  if (tool === "arjun") return "scans.slowArjun";
  if (tool === "nuclei" || tool === "nuclei-dast") return "scans.slowNuclei";
  if (tool === "amass") return "scans.slowAmass";
  return "scans.slowGeneric";
}

function StageRow({ tool, state, run }: { tool: string; state: StageState; run?: ToolRun }) {
  const { t } = useTranslation();
  const stage = STAGES[tool] || { key: tool, tool };
  const icon: Record<StageState, React.ReactNode> = {
    completed: <span className="text-emerald-400">✓</span>,
    running: <Spinner />,
    partial: <span className="text-amber-300">!</span>,
    failed: <span className="text-rose-400">✕</span>,
    waiting: <span className="text-slate-600">○</span>,
    skippedUnauth: <span className="text-slate-600">—</span>,
    notApplicable: <span className="text-slate-600">—</span>,
    notRun: <span className="text-slate-600">—</span>,
    cancelledStage: <span className="text-slate-600">—</span>,
  };
  const labelColor =
    state === "completed" ? "text-slate-100"
    : state === "running" ? "text-sky-300"
    : state === "partial" ? "text-amber-200"
    : state === "failed" ? "text-rose-300"
    : "text-slate-500";
  const dur = run?.duration_seconds != null ? ` (${run.duration_seconds}s)` : "";
  // A running stage used to show only "Running…", with no elapsed time, for as long as
  // it took -- and the fan-out tools (ffuf, arjun) legitimately run for many minutes.
  // With nothing counting up, a slow tool is indistinguishable from a frozen one.
  // `duration_seconds` is null until the run finishes, so count from started_at instead.
  const elapsed = useLiveElapsed(run, state === "running");
  const statusText: Record<StageState, string> = {
    completed: t("scans.sCompleted") + dur,
    running: t("scans.sRunning") + (elapsed != null ? ` (${fmtElapsed(elapsed)})` : ""),
    partial: t("scans.sPartial") + dur,
    failed: t("scans.sFailed") + dur,
    waiting: t("scans.sWaiting"),
    skippedUnauth: t("scans.sSkippedUnauth"),
    notApplicable: t("scans.sNotApplicable"),
    notRun: t("scans.sNotRun"),
    cancelledStage: t("scans.sCancelled"),
  };
  const statusColor =
    state === "completed" ? "text-emerald-400"
    : state === "running" ? "text-sky-400"
    : state === "partial" ? "text-amber-300"
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
      {state === "running" && elapsed != null && elapsed > SLOW_STAGE_SECONDS && (
        <div className="ms-8 mt-1.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-2.5 py-1.5 text-xs text-amber-300">
          {t(slowHintKey(tool))}
        </div>
      )}
      {state === "failed" && run?.error_message && (
        <div className="ms-8 mt-1.5 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 font-mono text-xs text-rose-300">
          <Ltr>{run.error_message}</Ltr>
        </div>
      )}
    </li>
  );
}
