"use client";

import { useCallback, useEffect, useState } from "react";

import { scanApi, type Scan, type Target } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { usePipeline } from "@/lib/pipeline";
import { Badge, Button, Card, Empty, ErrorText, Label, Select, Spinner } from "@/components/ui";
import { ScanProgress } from "@/components/project/ScanProgress";
import { SchedulesPanel } from "@/components/project/SchedulesPanel";

// The selectable tools come from the backend registry (lib/pipeline.ts), NOT from a
// hardcoded list here. The old list carried only 8 of the 12 registered tools --
// amass, dnsx, whatweb and ffuf were installed and runnable but could not be selected
// at all -- and `requires_active_testing` was duplicated here too, where it could
// disagree with the runner classes that actually enforce it (base.py).
const RUNNING = new Set(["queued", "pending", "running"]);
// Passive/recon defaults: safe to run without an active-testing authorization scope.
// Active tools (ffuf/arjun/nuclei/nuclei-dast) stay opt-in per scan.
const DEFAULT_MODULES = ["subfinder", "httpx", "naabu", "nmap", "katana"];

// Backend scan_type is Literal["web","api","network","cloud"] — derive it from the
// selected target's type rather than sending a fixed value.
const TARGET_SCAN_TYPE: Record<string, string> = {
  domain: "web",
  api: "api",
  ip_range: "network",
  cloud_account: "cloud",
  repo: "web",
};

export function ScansTab({ projectId, targets }: { projectId: string; targets: Target[] }) {
  const { t } = useTranslation();
  const pipeline = usePipeline();
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState("");

  const [targetId, setTargetId] = useState("");
  const [modules, setModules] = useState<string[]>(DEFAULT_MODULES);
  const [useAi, setUseAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [openScan, setOpenScan] = useState<string | null>(null);
  const [cancellingIds, setCancellingIds] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    try {
      setScans(await scanApi.list(projectId));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  // poll while any scan is running
  const anyRunning = scans?.some((s) => RUNNING.has(s.status));
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(load, 4000);
    return () => clearInterval(t);
  }, [anyRunning, load]);

  useEffect(() => {
    if (!targetId && targets.length) setTargetId(targets[0].id);
  }, [targets, targetId]);

  function toggleModule(m: string) {
    setModules((prev) => (prev.includes(m) ? prev.filter((x) => x !== m) : [...prev, m]));
  }

  // "Select all" is a pure selection shortcut over the SAME tool names the checkboxes
  // use -- there is deliberately no "all tools" scan mode on the wire. The request still
  // carries the explicit list, so the server's active-testing authorization check
  // (modules/scans/service.py) sees exactly the tools it would see from hand-picking,
  // and a target without active-testing scope is rejected identically.
  //
  // Derived from `modules`, never stored: a separate boolean would have to be kept in
  // sync with every individual toggle, and deselecting one tool after "select all" would
  // leave the control stuck on "clear all".
  const allSelected = pipeline.length > 0 && pipeline.every((p) => modules.includes(p.name));

  function toggleAllModules() {
    // Rebuilt from the pipeline rather than appended to the current selection, so the
    // result cannot contain a duplicate or a tool the registry no longer lists.
    setModules(allSelected ? [] : pipeline.map((p) => p.name));
  }

  async function createScan(e: React.FormEvent) {
    e.preventDefault();
    if (!targetId || modules.length === 0) return;
    setBusy(true);
    setError("");
    try {
      // ordering is deterministic server-side; scan_type is derived from the target type
      const ordered = pipeline.map((p) => p.name).filter((m) => modules.includes(m));
      const target = targets.find((t) => t.id === targetId);
      const scanType = TARGET_SCAN_TYPE[target?.type ?? ""] ?? "web";
      await scanApi.create(projectId, targetId, scanType, ordered, useAi);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const targetLabel = (id: string) => targets.find((t) => t.id === id)?.value ?? id.slice(0, 8);

  async function cancelScan(scanId: string) {
    setCancellingIds((prev) => new Set(prev).add(scanId));
    setError("");
    try {
      await scanApi.cancel(projectId, scanId);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setCancellingIds((prev) => {
        const next = new Set(prev);
        next.delete(scanId);
        return next;
      });
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <h3 className="mb-3 font-medium">{t("scans.newScan")}</h3>
        {targets.length === 0 ? (
          <Empty>{t("scans.addVerifyFirst")}</Empty>
        ) : (
          <form onSubmit={createScan} className="space-y-4">
            <div className="max-w-sm">
              <Label>{t("scans.target")}</Label>
              <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.value} ({t.type})
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <div className="flex items-center justify-between gap-3">
                <Label>{t("scans.modules")}</Label>
                {/* type="button": inside a <form>, a bare <button> defaults to submit and
                    would start the scan instead of changing the selection. */}
                <button
                  type="button"
                  onClick={toggleAllModules}
                  disabled={pipeline.length === 0}
                  className="text-xs text-sky-400 underline-offset-2 hover:underline disabled:opacity-50"
                >
                  {allSelected ? t("scans.clearAll") : t("scans.selectAll")}
                </button>
              </div>
              <div className="flex flex-wrap gap-3">
                {pipeline.map((p) => (
                  <label
                    key={p.name}
                    className="flex items-center gap-2 text-sm text-slate-300"
                    // Surfaced up front rather than after the fact: a tool whose binary is
                    // missing from the worker records a failed ToolRun and contributes no
                    // findings, which in a finished report is indistinguishable from
                    // "ran and found nothing".
                    title={p.binary_available === false ? t("scans.toolUnavailableHint", { binary: p.binary }) : undefined}
                  >
                    <input type="checkbox" checked={modules.includes(p.name)} onChange={() => toggleModule(p.name)} />
                    <span dir="ltr" className={p.binary_available === false ? "text-slate-500 line-through" : undefined}>
                      {p.name}
                    </span>
                    {p.requires_active_testing && (
                      <span className="text-xs text-amber-400">({t("scans.active")})</span>
                    )}
                    {p.produces_vulnerabilities && (
                      <span className="text-xs text-rose-300">({t("scans.findsVulns")})</span>
                    )}
                    {p.binary_available === false && (
                      <span className="text-xs text-slate-500">({t("scans.toolUnavailable")})</span>
                    )}
                  </label>
                ))}
              </div>
              <p className="mt-1 text-xs text-slate-500">{t("scans.activeNote")}</p>
              {/* Only nuclei/nuclei-dast can write a Vulnerability row; every other tool
                  inventories assets. Without this, a scan of recon-only tools completing
                  with an empty vulnerability list reads as "you're clean" rather than
                  "nothing was tested for vulnerabilities". */}
              <p className="mt-1 text-xs text-slate-500">{t("scans.vulnToolsNote")}</p>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
              {t("scans.useAiPlanner")}
            </label>
            {useAi && <p className="-mt-2 ms-6 text-xs text-amber-400/80">{t("scans.aiPlannerHint")}</p>}
            <Button type="submit" disabled={busy || !targetId || modules.length === 0}>
              {busy ? t("scans.starting") : t("scans.startScan")}
            </Button>
          </form>
        )}
      </Card>

      <SchedulesPanel projectId={projectId} targets={targets} />

      <ErrorText>{error}</ErrorText>

      {scans === null ? (
        <Spinner />
      ) : scans.length === 0 ? (
        <Empty>{t("scans.noScans")}</Empty>
      ) : (
        <div className="space-y-3">
          {scans.map((s) => (
            <Card key={s.id}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <Badge kind="status" value={s.status} />
                    <span className="font-mono text-sm text-slate-200">{targetLabel(s.target_id)}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    <span dir="ltr">{(s.config?.requested_modules || []).join(", ") || s.scan_type}</span> ·{" "}
                    {t("scans.started")} {new Date(s.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {RUNNING.has(s.status) && <Spinner />}
                  {RUNNING.has(s.status) && (
                    <Button
                      variant="danger"
                      disabled={cancellingIds.has(s.id)}
                      onClick={() => cancelScan(s.id)}
                    >
                      {cancellingIds.has(s.id) ? t("scans.cancelling") : t("scans.cancel")}
                    </Button>
                  )}
                  <Button variant="ghost" onClick={() => setOpenScan(openScan === s.id ? null : s.id)}>
                    {openScan === s.id ? t("scans.hide") : t("scans.progress")}
                  </Button>
                </div>
              </div>
              {(openScan === s.id || RUNNING.has(s.status)) && <ScanProgress projectId={projectId} scan={s} />}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
