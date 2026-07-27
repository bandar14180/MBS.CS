"use client";

import { useCallback, useEffect, useState } from "react";

import { reportApi, type Report } from "@/lib/api";
import { Button, Card, Empty, ErrorText, Spinner } from "@/components/ui";

const TYPES = [
  { value: "executive", label: "Executive summary" },
  { value: "technical", label: "Technical detail" },
];

export function ReportsTab({ projectId }: { projectId: string }) {
  const [reports, setReports] = useState<Report[] | null>(null);
  const [error, setError] = useState("");
  const [busyType, setBusyType] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setReports(await reportApi.list(projectId));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  async function generate(type: string) {
    setBusyType(type);
    setError("");
    try {
      await reportApi.create(projectId, type);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusyType(null);
    }
  }

  async function download(r: Report) {
    setDownloading(r.id);
    setError("");
    try {
      const blob = await reportApi.download(projectId, r.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mbs-${r.type}-${r.id.slice(0, 8)}.${r.format || "pdf"}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <h3 className="mb-3 font-medium">Generate report</h3>
        <div className="flex flex-wrap gap-3">
          {TYPES.map((t) => (
            <Button key={t.value} variant="secondary" onClick={() => generate(t.value)} disabled={busyType !== null}>
              {busyType === t.value ? "Generating…" : t.label}
            </Button>
          ))}
        </div>
      </Card>

      <ErrorText>{error}</ErrorText>

      {reports === null ? (
        <Spinner />
      ) : reports.length === 0 ? (
        <Empty>No reports yet. Generate one from the current findings.</Empty>
      ) : (
        <div className="space-y-3">
          {reports.map((r) => (
            <Card key={r.id}>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium capitalize text-slate-100">{r.type} report</div>
                  <div className="text-xs text-slate-500">
                    {(r.format || "pdf").toUpperCase()} · {new Date(r.generated_at).toLocaleString()}
                  </div>
                </div>
                <Button onClick={() => download(r)} disabled={downloading === r.id}>
                  {downloading === r.id ? "Downloading…" : "Download"}
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
