"use client";

import { useEffect, useState } from "react";

import { ApiError, auditApi, type AuditEvent } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Card, Empty, Spinner } from "@/components/ui";

export default function AuditPage() {
  const { t } = useTranslation();
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    auditApi
      .list()
      .then(setEvents)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 403) setDenied(true);
        setEvents([]);
      });
  }, []);

  return (
    <div className="mx-auto max-w-4xl">
      <h1 className="mb-1 text-2xl font-semibold text-white">{t("audit.title")}</h1>
      <p className="mb-6 text-sm text-slate-400">{t("audit.subtitle")}</p>

      {events === null ? (
        <Spinner />
      ) : denied ? (
        <Card>
          <Empty>{t("audit.denied")}</Empty>
        </Card>
      ) : events.length === 0 ? (
        <Card>
          <Empty>{t("audit.empty")}</Empty>
        </Card>
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-cyber-border/60 text-start text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-4 py-3 text-start">{t("audit.action")}</th>
                  <th className="px-4 py-3 text-start">{t("audit.actor")}</th>
                  <th className="px-4 py-3 text-start">{t("audit.detail")}</th>
                  <th className="px-4 py-3 text-start">{t("audit.when")}</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id} className="border-b border-cyber-border/30">
                    <td className="px-4 py-3">
                      <span className="rounded-md bg-white/5 px-2 py-0.5 font-mono text-xs text-accent-cyan" dir="ltr">
                        {e.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-300" dir="ltr">{e.actor_email || "—"}</td>
                    <td className="px-4 py-3 text-slate-400" dir="ltr">{e.detail || "—"}</td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">
                      {new Date(e.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
