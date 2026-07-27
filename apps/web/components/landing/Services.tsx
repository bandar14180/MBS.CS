"use client";

import { useTranslation } from "@/lib/i18n";
import { Icons, type IconKey } from "@/components/landing/icons";

const SERVICES: { key: string; icon: IconKey; featured?: boolean }[] = [
  { key: "aiPentest", icon: "ai", featured: true },
  { key: "web", icon: "web" },
  { key: "api", icon: "api" },
  { key: "cloud", icon: "cloud" },
  { key: "network", icon: "network" },
  { key: "vuln", icon: "vuln" },
  { key: "reporting", icon: "report" },
];

export function Services() {
  const { t } = useTranslation();
  return (
    <section id="services" className="relative py-24">
      <div className="mx-auto max-w-7xl px-5">
        <SectionHeading eyebrow={t("nav.services")} title={t("services.title")} subtitle={t("services.subtitle")} />
        <div className="mt-14 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {SERVICES.map(({ key, icon, featured }) => {
            const Icon = Icons[icon];
            return (
              <div
                key={key}
                className={`group relative overflow-hidden rounded-2xl border p-6 transition duration-300 hover:-translate-y-1 ${
                  featured
                    ? "border-accent-cyan/30 bg-gradient-to-br from-accent-cyan/10 to-accent-violet/10 lg:row-span-1"
                    : "border-cyber-border/60 bg-white/[0.02] hover:border-accent-cyan/30 hover:bg-white/[0.04]"
                }`}
              >
                <div className="absolute -right-8 -top-8 h-24 w-24 rounded-full bg-accent-cyan/10 opacity-0 blur-2xl transition group-hover:opacity-100" />
                <div className="mb-4 inline-flex h-12 w-12 items-center justify-center rounded-xl border border-accent-cyan/25 bg-accent-cyan/10 text-accent-cyan">
                  <Icon className="h-6 w-6" />
                </div>
                <h3 className="text-base font-semibold text-white">{t(`services.${key}.title`)}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{t(`services.${key}.desc`)}</p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

export function SectionHeading({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle: string }) {
  return (
    <div className="mx-auto max-w-2xl text-center">
      <span className="text-xs font-semibold uppercase tracking-[0.2em] text-accent-cyan">{eyebrow}</span>
      <h2 className="mt-3 text-3xl font-bold tracking-tight text-white sm:text-4xl">{title}</h2>
      <p className="mt-4 text-pretty text-base text-slate-400">{subtitle}</p>
    </div>
  );
}
