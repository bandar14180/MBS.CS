"use client";

import { useCallback, useEffect, useState } from "react";

import { scheduleApi, type ScanSchedule, type Target } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Badge, Button, Card, Empty, ErrorText, Label, Select, Spinner } from "@/components/ui";

const MODULES = ["subfinder", "httpx", "naabu", "nmap", "nuclei"];
const FREQUENCIES = [
  { minutes: 60, key: "schedules.hourly" },
  { minutes: 360, key: "schedules.every6h" },
  { minutes: 1440, key: "schedules.daily" },
  { minutes: 10080, key: "schedules.weekly" },
];
const TARGET_SCAN_TYPE: Record<string, string> = {
  domain: "web", api: "api", ip_range: "network", cloud_account: "cloud", repo: "web",
};

export function SchedulesPanel({ projectId, targets }: { projectId: string; targets: Target[] }) {
  const { t } = useTranslation();
  const [schedules, setSchedules] = useState<ScanSchedule[] | null>(null);
  const [error, setError] = useState("");
  const [targetId, setTargetId] = useState("");
  const [modules, setModules] = useState<string[]>(["subfinder", "httpx", "naabu", "nmap"]);
  const [interval, setInterval] = useState(1440);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setSchedules(await scheduleApi.list(projectId));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    if (!targetId && targets.length) setTargetId(targets[0].id);
  }, [targets, targetId]);

  function toggleModule(m: string) {
    setModules((p) => (p.includes(m) ? p.filter((x) => x !== m) : [...p, m]));
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!targetId || modules.length === 0) return;
    setBusy(true);
    setError("");
    try {
      const target = targets.find((x) => x.id === targetId);
      const scanType = TARGET_SCAN_TYPE[target?.type ?? ""] ?? "web";
      const ordered = MODULES.filter((m) => modules.includes(m));
      await scheduleApi.create(projectId, targetId, scanType, ordered, interval, false);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function toggle(s: ScanSchedule) {
    try {
      await scheduleApi.update(projectId, s.id, { enabled: !s.enabled });
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }
  async function remove(s: ScanSchedule) {
    try {
      await scheduleApi.remove(projectId, s.id);
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  const targetLabel = (id: string) => targets.find((x) => x.id === id)?.value ?? id.slice(0, 8);
  const freqLabel = (mins: number) => {
    const f = FREQUENCIES.find((x) => x.minutes === mins);
    return f ? t(f.key) : `${mins} min`;
  };

  return (
    <Card>
      <h3 className="mb-3 font-medium">{t("schedules.title")}</h3>
      {targets.length === 0 ? (
        <Empty>{t("scans.addVerifyFirst")}</Empty>
      ) : (
        <form onSubmit={create} className="space-y-3 border-b border-cyber-border/60 pb-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[14rem] flex-1">
              <Label>{t("scans.target")}</Label>
              <Select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                {targets.map((tg) => (
                  <option key={tg.id} value={tg.id}>
                    {tg.value} ({tg.type})
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <Label>{t("schedules.frequency")}</Label>
              <Select value={interval} onChange={(e) => setInterval(Number(e.target.value))}>
                {FREQUENCIES.map((f) => (
                  <option key={f.minutes} value={f.minutes}>
                    {t(f.key)}
                  </option>
                ))}
              </Select>
            </div>
            <Button type="submit" disabled={busy || !targetId || modules.length === 0}>
              {t("schedules.create")}
            </Button>
          </div>
          <div className="flex flex-wrap gap-3">
            {MODULES.map((m) => (
              <label key={m} className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={modules.includes(m)} onChange={() => toggleModule(m)} />
                <span dir="ltr">{m}</span>
              </label>
            ))}
          </div>
        </form>
      )}

      <ErrorText>{error}</ErrorText>

      {schedules === null ? (
        <Spinner />
      ) : schedules.length === 0 ? (
        <Empty>{t("schedules.none")}</Empty>
      ) : (
        <div className="mt-4 space-y-2">
          {schedules.map((s) => (
            <div key={s.id} className="rounded-lg border border-cyber-border/50 bg-white/[0.02] p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <Badge kind="status" value={s.enabled ? "running" : "queued"} />
                    <span className="font-mono text-sm text-slate-200" dir="ltr">{targetLabel(s.target_id)}</span>
                    <span className="text-xs text-slate-400">· {freqLabel(s.interval_minutes)}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    <span dir="ltr">{s.requested_modules.join(", ")}</span> · {t("schedules.nextRun")}:{" "}
                    {new Date(s.next_run_at).toLocaleString()}
                    {s.last_run_at && <> · {t("schedules.lastRun")}: {new Date(s.last_run_at).toLocaleString()}</>}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" onClick={() => toggle(s)}>
                    {s.enabled ? t("schedules.disable") : t("schedules.enable")}
                  </Button>
                  <Button variant="danger" onClick={() => remove(s)}>
                    {t("schedules.delete")}
                  </Button>
                </div>
              </div>
              {s.last_error && (
                <div className="ms-1 mt-2 rounded-md border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-xs text-rose-300">
                  {t("schedules.lastError")}: <span dir="ltr">{s.last_error}</span>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}
