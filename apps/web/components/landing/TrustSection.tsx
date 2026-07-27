"use client";

import { useTranslation } from "@/lib/i18n";
import { SectionHeading } from "@/components/landing/Services";
import { Icons, type IconKey } from "@/components/landing/icons";

const POINTS: { key: string; icon: IconKey }[] = [
  { key: "isolation", icon: "database" },
  { key: "authorization", icon: "lock" },
  { key: "evidence", icon: "shield" },
  { key: "frameworks", icon: "frameworks" },
];

const FRAMEWORKS = ["OWASP", "NIST", "ISO 27001", "PCI DSS"];

export function TrustSection() {
  const { t } = useTranslation();
  return (
    <section id="why" className="relative py-24">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading eyebrow={t("nav.why")} title={t("trust.title")} subtitle={t("trust.subtitle")} />

        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {POINTS.map(({ key, icon }) => {
            const Icon = Icons[icon];
            return (
              <div key={key} className="rounded-2xl border border-cyber-border/60 bg-white/[0.02] p-6">
                <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl border border-emerald-400/25 bg-emerald-400/10 text-emerald-300">
                  <Icon className="h-6 w-6" />
                </div>
                <h3 className="text-base font-semibold text-white">{t(`trust.${key}.title`)}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{t(`trust.${key}.desc`)}</p>
              </div>
            );
          })}
        </div>

        <div className="mt-12 flex flex-wrap items-center justify-center gap-3">
          {FRAMEWORKS.map((f) => (
            <span
              key={f}
              className="rounded-full border border-cyber-border/70 bg-white/[0.03] px-5 py-2 text-sm font-semibold tracking-wide text-slate-300"
            >
              {f}
            </span>
          ))}
        </div>
      </div>
    </section>
  );
}
