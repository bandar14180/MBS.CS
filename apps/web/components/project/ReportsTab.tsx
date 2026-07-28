"use client";

import { useCallback, useEffect, useState } from "react";

import { reportApi, type Report } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Button, Card, Empty, ErrorText, Spinner } from "@/components/ui";

const TYPES = [
  { value: "executive", labelKey: "reports.executive" },
  { value: "technical", labelKey: "reports.technical" },
];

export function ReportsTab({ projectId }: { projectId: string }) {
  const { t } = useTranslation();
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
        <h3 className="mb-3 font-medium">{t("reports.generateReport")}</h3>
        <div className="flex flex-wrap gap-3">
          {TYPES.map((ty) => (
            <Button key={ty.value} variant="secondary" onClick={() => generate(ty.value)} disabled={busyType !== null}>
              {busyType === ty.value ? t("reports.generating") : t(ty.labelKey)}
            </Button>
          ))}
        </div>
      </Card>

      <ErrorText>{error}</ErrorText>

      {reports === null ? (
        <Spinner />
      ) : reports.length === 0 ? (
        <Empty>{t("reports.empty")}</Empty>
      ) : (
        <div className="space-y-3">
          {reports.map((r) => (
            <Card key={r.id}>
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="font-medium text-slate-100">
                    {t(`reports.${r.type}`)} · {t("reports.report")}
                  </div>
                  <div className="text-xs text-slate-500">
                    <span dir="ltr">{(r.format || "pdf").toUpperCase()}</span> ·{" "}
                    {new Date(r.generated_at).toLocaleString()}
                  </div>
                </div>
                <Button onClick={() => download(r)} disabled={downloading === r.id}>
                  {downloading === r.id ? t("reports.downloading") : t("reports.download")}
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
