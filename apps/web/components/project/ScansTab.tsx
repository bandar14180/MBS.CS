"use client";

import { useCallback, useEffect, useState } from "react";

import { scanApi, type Scan, type Target } from "@/lib/api";
import { Badge, Button, Card, Empty, ErrorText, Label, Select, Spinner } from "@/components/ui";
import { ScanProgress } from "@/components/project/ScanProgress";

const MODULES = ["subfinder", "httpx", "naabu", "nmap", "nuclei"];
const ACTIVE_MODULES = new Set(["nuclei"]);
const RUNNING = new Set(["queued", "pending", "running"]);

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
  const [scans, setScans] = useState<Scan[] | null>(null);
  const [error, setError] = useState("");

  const [targetId, setTargetId] = useState("");
  const [modules, setModules] = useState<string[]>(["subfinder", "httpx", "naabu", "nmap"]);
  const [useAi, setUseAi] = useState(false);
  const [busy, setBusy] = useState(false);
  const [openScan, setOpenScan] = useState<string | null>(null);

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

  async function createScan(e: React.FormEvent) {
    e.preventDefault();
    if (!targetId || modules.length === 0) return;
    setBusy(true);
    setError("");
    try {
      // ordering is deterministic server-side; scan_type is derived from the target type
      const ordered = MODULES.filter((m) => modules.includes(m));
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

  return (
    <div className="space-y-6">
      <Card>
        <h3 className="mb-3 font-medium">New scan</h3>
        {targets.length === 0 ? (
          <Empty>Add and verify a target first.</Empty>
        ) : (
          <form onSubmit={createScan} className="space-y-4">
            <div className="max-w-sm">
              <Label>Target</Label>
              <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.value} ({t.type})
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <Label>Modules</Label>
              <div className="flex flex-wrap gap-3">
                {MODULES.map((m) => (
                  <label key={m} className="flex items-center gap-2 text-sm text-slate-300">
                    <input type="checkbox" checked={modules.includes(m)} onChange={() => toggleModule(m)} />
                    {m}
                    {ACTIVE_MODULES.has(m) && <span className="text-xs text-amber-400">(active)</span>}
                  </label>
                ))}
              </div>
              <p className="mt-1 text-xs text-slate-500">
                Active modules require a target with active-testing authorization.
              </p>
            </div>
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
              Use AI planner (falls back to deterministic order if unavailable)
            </label>
            <Button type="submit" disabled={busy || !targetId || modules.length === 0}>
              {busy ? "Starting…" : "Start scan"}
            </Button>
          </form>
        )}
      </Card>

      <ErrorText>{error}</ErrorText>

      {scans === null ? (
        <Spinner />
      ) : scans.length === 0 ? (
        <Empty>No scans yet.</Empty>
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
                    {(s.config?.requested_modules || []).join(", ") || s.scan_type} · started{" "}
                    {new Date(s.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {RUNNING.has(s.status) && <Spinner />}
                  <Button variant="ghost" onClick={() => setOpenScan(openScan === s.id ? null : s.id)}>
                    {openScan === s.id ? "Hide" : "Progress"}
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
