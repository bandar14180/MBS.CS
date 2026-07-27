"use client";

import { useTranslation } from "@/lib/i18n";
import { SectionHeading } from "@/components/landing/Services";
import { Icons, type IconKey } from "@/components/landing/icons";

const AGENTS: { key: string; icon: IconKey; n: string }[] = [
  { key: "recon", icon: "recon", n: "01" },
  { key: "vulnAnalysis", icon: "vuln", n: "02" },
  { key: "validation", icon: "validate", n: "03" },
  { key: "risk", icon: "risk", n: "04" },
  { key: "report", icon: "report", n: "05" },
];

const FLOW = ["target", "recon", "analysis", "discovery", "validation", "risk", "report"];

export function AgentsWorkflow() {
  const { t } = useTranslation();
  return (
    <section id="agents" className="relative overflow-hidden py-24">
      <div className="pointer-events-none absolute inset-0 bg-radial-glow opacity-60" />
      <div className="relative mx-auto max-w-7xl px-5">
        <SectionHeading eyebrow={t("nav.agents")} title={t("agents.title")} subtitle={t("agents.subtitle")} />

        {/* Pipeline flow */}
        <div className="mt-14 overflow-x-auto">
          <div className="mx-auto flex min-w-max items-center justify-center gap-2 rounded-2xl glass px-5 py-5">
            {FLOW.map((step, i) => (
              <div key={step} className="flex items-center gap-2">
                <div
                  className={`whitespace-nowrap rounded-lg px-3 py-2 text-xs font-medium ${
                    i === 0
                      ? "border border-accent-violet/40 bg-accent-violet/15 text-white"
                      : i === FLOW.length - 1
                      ? "border border-emerald-400/40 bg-emerald-400/10 text-emerald-300"
                      : "border border-accent-cyan/25 bg-accent-cyan/10 text-accent-cyan"
                  }`}
                >
                  {t(`agents.flow.${step}`)}
                </div>
                {i < FLOW.length - 1 && (
                  <svg width="26" height="10" viewBox="0 0 26 10" className="flip-rtl text-accent-cyan/60" fill="none">
                    <path d="M0 5h20" stroke="currentColor" strokeWidth="1.5" strokeDasharray="4 4" className="animate-flow-dash" />
                    <path d="M19 1l5 4-5 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Agent cards */}
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          {AGENTS.map(({ key, icon, n }) => {
            const Icon = Icons[icon];
            return (
              <div
                key={key}
                className="group relative overflow-hidden rounded-2xl border border-cyber-border/60 bg-white/[0.02] p-5 transition duration-300 hover:-translate-y-1 hover:border-accent-violet/40"
              >
                <span className="absolute end-4 top-3 font-mono text-xs text-slate-600 transition group-hover:text-accent-violet/70">
                  {n}
                </span>
                <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-accent-violet/25 bg-accent-violet/10 text-accent-violet shadow-glow-violet">
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="text-sm font-semibold text-white">{t(`agents.${key}.title`)}</h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">{t(`agents.${key}.desc`)}</p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
