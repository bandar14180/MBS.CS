"use client";

import { useCallback, useEffect, useState } from "react";

import { assetApi, type Asset } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Card, Empty, ErrorText, Label, Select, Spinner } from "@/components/ui";

const TYPE_LABELS: Record<string, string> = {
  subdomain: "Subdomains",
  http_service: "Live web services",
  port: "Open ports",
  service: "Detected services",
  url: "Crawled URLs",
};

// Recon pipeline order, so the summary reads top-to-bottom the same way a scan runs.
const TYPE_ORDER = ["subdomain", "http_service", "port", "service", "url"];

function summarize(a: Asset): string {
  const m = a.metadata || {};
  switch (a.asset_type) {
    case "subdomain":
      return m.source ? `source: ${m.source}` : "";
    case "http_service":
      return [
        m.status_code != null ? `status ${m.status_code}` : null,
        m.webserver || null,
        m.title ? `"${m.title}"` : null,
        Array.isArray(m.tech) && m.tech.length ? m.tech.join(", ") : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "port":
      return m.protocol ? String(m.protocol).toUpperCase() : "";
    case "service":
      return [m.protocol ? String(m.protocol).toUpperCase() : null, m.product, m.version].filter(Boolean).join(" ");
    case "url":
      return m.source ? `via ${m.source}${m.has_params ? " · has params" : ""}` : "";
    default:
      return "";
  }
}

export function AssetsTab({ projectId }: { projectId: string }) {
  const { t } = useTranslation();
  const [assets, setAssets] = useState<Asset[] | null>(null);
  const [error, setError] = useState("");
  const [type, setType] = useState("");

  const load = useCallback(async () => {
    try {
      setAssets(await assetApi.list(projectId));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  if (assets === null) return <Spinner />;

  const types = Array.from(new Set(assets.map((a) => a.asset_type)));
  const orderedTypes = [...TYPE_ORDER.filter((tt) => types.includes(tt)), ...types.filter((tt) => !TYPE_ORDER.includes(tt))];
  const visibleTypes = type ? orderedTypes.filter((tt) => tt === type) : orderedTypes;

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <Label>{t("assets.type")}</Label>
            <Select value={type} onChange={(e) => setType(e.target.value)}>
              <option value="">{t("assets.all")}</option>
              {types.map((tt) => (
                <option key={tt} value={tt}>
                  {TYPE_LABELS[tt] || tt}
                </option>
              ))}
            </Select>
          </div>
          <div className="text-xs text-slate-500">{t("assets.total", { count: assets.length })}</div>
        </div>
      </Card>

      <ErrorText>{error}</ErrorText>

      {assets.length === 0 ? (
        <Empty>{t("assets.empty")}</Empty>
      ) : (
        visibleTypes.map((tt) => {
          const items = assets.filter((a) => a.asset_type === tt);
          if (items.length === 0) return null;
          return (
            <Card key={tt}>
              <div className="mb-3 text-xs font-medium uppercase tracking-wide text-slate-500">
                {TYPE_LABELS[tt] || tt} ({items.length})
              </div>
              <div className="space-y-2">
                {items.map((a) => (
                  <div
                    key={a.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-cyber-border/60 bg-white/[0.02] px-3 py-2"
                  >
                    <span className="font-mono text-sm text-slate-100" dir="ltr">
                      {a.value}
                    </span>
                    <span className="text-xs text-slate-500" dir="ltr">
                      {summarize(a)}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          );
        })
      )}
    </div>
  );
}
