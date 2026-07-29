"use client";

import { useEffect, useState } from "react";

import { aiApi, type AIStatus } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Card } from "@/components/ui";
import { Icons } from "@/components/landing/icons";

const AGENTS: { key: string; icon: keyof typeof Icons }[] = [
  { key: "recon", icon: "recon" },
  { key: "vulnAnalysis", icon: "vuln" },
  { key: "validation", icon: "validate" },
  { key: "risk", icon: "risk" },
  { key: "report", icon: "report" },
];

export function AiAgentsPanel() {
  const { t } = useTranslation();
  const [status, setStatus] = useState<AIStatus | null>(null);

  useEffect(() => {
    aiApi.status().then(setStatus).catch(() => setStatus({ enabled: false, model: "" }));
  }, []);

  return (
    <Card className="mb-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-500">{t("aiAgents.title")}</div>
          <div className="mt-0.5 text-sm text-slate-400">{t("aiAgents.subtitle")}</div>
        </div>
        {status && (
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${
              status.enabled
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                : "border-amber-500/40 bg-amber-500/10 text-amber-300"
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${status.enabled ? "bg-emerald-400" : "bg-amber-400"}`} />
            {status.enabled ? t("aiAgents.active") : t("aiAgents.inactive")}
          </span>
        )}
      </div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {AGENTS.map(({ key, icon }) => {
          const Icon = Icons[icon];
          return (
            <div key={key} className="rounded-xl border border-cyber-border/60 bg-white/[0.02] p-3">
              <div className="mb-2 inline-flex h-9 w-9 items-center justify-center rounded-lg border border-accent-violet/25 bg-accent-violet/10 text-accent-violet">
                <Icon className="h-4 w-4" />
              </div>
              <div className="text-xs font-medium text-slate-100">{t(`agents.${key}.title`)}</div>
            </div>
          );
        })}
      </div>
      {status && !status.enabled && (
        <p className="mt-3 text-xs text-slate-500">{t("aiAgents.configureHint")}</p>
      )}
    </Card>
  );
}
