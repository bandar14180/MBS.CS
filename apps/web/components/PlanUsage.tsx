"use client";

import { useEffect, useState } from "react";

import { billingApi, type PlanCatalogItem, type Usage } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Card, Select, Spinner } from "@/components/ui";

function UsageBar({ label, used, limit, unlimitedLabel }: { label: string; used: number; limit: number | null; unlimitedLabel: string }) {
  const pct = limit ? Math.min(100, Math.round((used / limit) * 100)) : 0;
  const near = limit != null && used >= limit;
  const warn = limit != null && !near && used / limit >= 0.8;
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs">
        <span className="text-slate-400">{label}</span>
        <span className="font-mono text-slate-300" dir="ltr">
          {used} / {limit ?? "∞"}
        </span>
      </div>
      {limit == null ? (
        <div className="text-xs text-emerald-400">{unlimitedLabel}</div>
      ) : (
        <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
          <div
            className={`h-full rounded-full ${near ? "bg-rose-500" : warn ? "bg-amber-400" : "bg-gradient-to-r from-accent-cyan to-accent-violet"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
    </div>
  );
}

export function PlanUsage() {
  const { t } = useTranslation();
  const [usage, setUsage] = useState<Usage | null>(null);
  const [plans, setPlans] = useState<PlanCatalogItem[]>([]);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [u, p] = await Promise.all([billingApi.usage(), billingApi.plans()]);
      setUsage(u);
      setPlans(p);
    } catch {}
  }
  useEffect(() => {
    load();
  }, []);

  async function change(tier: string) {
    if (!tier || tier === usage?.plan_tier) return;
    setBusy(true);
    try {
      setUsage(await billingApi.setPlan(tier));
    } catch {
    } finally {
      setBusy(false);
    }
  }

  if (!usage) return null;

  // pilot (default/beta) isn't a selectable customer tier; still show usage.
  const selectable = plans.map((p) => p.tier);

  return (
    <Card className="mb-6">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-500">{t("billing.planUsage")}</div>
          <div className="mt-0.5 flex items-baseline gap-2">
            <span className="text-lg font-semibold text-white">{usage.plan_name}</span>
            {usage.price_usd_month > 0 && (
              <span className="text-xs text-slate-400" dir="ltr">
                ${usage.price_usd_month}
                {t("billing.perMonth")}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {busy && <Spinner />}
          <Select
            value={selectable.includes(usage.plan_tier) ? usage.plan_tier : ""}
            onChange={(e) => change(e.target.value)}
            aria-label={t("billing.changePlan")}
          >
            {!selectable.includes(usage.plan_tier) && <option value="">{usage.plan_name}</option>}
            {plans.map((p) => (
              <option key={p.tier} value={p.tier}>
                {p.name}
              </option>
            ))}
          </Select>
        </div>
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <UsageBar label={t("billing.projects")} used={usage.usage.projects} limit={usage.limits.projects} unlimitedLabel={t("billing.unlimited")} />
        <UsageBar label={t("billing.targets")} used={usage.usage.targets} limit={usage.limits.targets} unlimitedLabel={t("billing.unlimited")} />
        <UsageBar label={t("billing.scansThisMonth")} used={usage.usage.scans_this_month} limit={usage.limits.scans_per_month} unlimitedLabel={t("billing.unlimited")} />
      </div>
    </Card>
  );
}
