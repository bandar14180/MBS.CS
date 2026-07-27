"use client";

import Link from "next/link";

import { useTranslation } from "@/lib/i18n";

export function Hero() {
  const { t } = useTranslation();

  return (
    <section className="relative overflow-hidden pt-36 pb-24">
      <div className="pointer-events-none absolute inset-0 bg-grid mask-fade-b" />
      <div className="pointer-events-none absolute inset-0 bg-radial-glow" />
      {/* floating accent orbs */}
      <div className="pointer-events-none absolute -left-24 top-32 h-72 w-72 rounded-full bg-accent-violet/20 blur-3xl animate-float" />
      <div className="pointer-events-none absolute -right-16 top-52 h-64 w-64 rounded-full bg-accent-cyan/20 blur-3xl animate-float" style={{ animationDelay: "2s" }} />

      <div className="relative mx-auto max-w-7xl px-5">
        <div className="mx-auto max-w-3xl text-center">
          <div className="mb-6 inline-flex animate-fade-up items-center gap-2 rounded-full border border-accent-cyan/30 bg-accent-cyan/10 px-4 py-1.5 text-xs font-medium text-accent-cyan">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent-cyan opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-accent-cyan" />
            </span>
            {t("hero.badge")}
          </div>

          <h1 className="animate-fade-up text-balance text-4xl font-bold leading-[1.1] tracking-tight sm:text-6xl" style={{ animationDelay: "0.05s" }}>
            <span className="text-gradient">{t("hero.title")}</span>
          </h1>

          <p className="mx-auto mt-6 max-w-2xl animate-fade-up text-pretty text-base text-slate-300 sm:text-lg" style={{ animationDelay: "0.12s" }}>
            {t("hero.subtitle")}
          </p>

          <div className="mt-9 flex animate-fade-up flex-col items-center justify-center gap-3 sm:flex-row" style={{ animationDelay: "0.2s" }}>
            <Link href="/register" className="btn-gradient w-full rounded-xl px-6 py-3.5 text-sm font-semibold text-white shadow-glow sm:w-auto">
              {t("hero.ctaPrimary")}
            </Link>
            <a href="#agents" className="w-full rounded-xl border border-cyber-border bg-white/5 px-6 py-3.5 text-sm font-semibold text-slate-100 transition hover:border-accent-cyan/40 hover:bg-white/10 sm:w-auto">
              {t("hero.ctaSecondary")}
            </a>
          </div>

          <div className="mt-12 flex animate-fade-up flex-wrap items-center justify-center gap-x-10 gap-y-4 text-center" style={{ animationDelay: "0.28s" }}>
            <Stat value="5" label={t("hero.stats.agents")} />
            <span className="hidden h-8 w-px bg-cyber-border sm:block" />
            <Stat value="4" label={t("hero.stats.frameworks")} />
            <span className="hidden h-8 w-px bg-cyber-border sm:block" />
            <Stat value="100%" label={t("hero.stats.evidence")} />
          </div>
        </div>

        <DashboardPreview />
      </div>
    </section>
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="text-xs text-slate-400">{label}</div>
    </div>
  );
}

// Stylized product screenshot — pure CSS/SVG so it stays self-contained and crisp.
function DashboardPreview() {
  const bars = [
    { label: "Critical", w: "78%", c: "bg-rose-500" },
    { label: "High", w: "60%", c: "bg-orange-500" },
    { label: "Medium", w: "42%", c: "bg-amber-400" },
    { label: "Low", w: "24%", c: "bg-sky-400" },
  ];
  return (
    <div className="relative mx-auto mt-16 max-w-5xl animate-fade-up" style={{ animationDelay: "0.36s" }}>
      <div className="absolute inset-x-8 -top-6 h-24 rounded-full bg-accent-cyan/20 blur-3xl" />
      <div className="relative overflow-hidden rounded-2xl glass-strong shadow-glow-violet">
        <div className="flex items-center gap-2 border-b border-cyber-border/60 px-4 py-3">
          <span className="h-3 w-3 rounded-full bg-rose-500/80" />
          <span className="h-3 w-3 rounded-full bg-amber-400/80" />
          <span className="h-3 w-3 rounded-full bg-emerald-400/80" />
          <span className="ms-3 text-xs text-slate-400">mbs.sc / dashboard</span>
        </div>
        <div className="grid gap-4 p-5 sm:grid-cols-3">
          <div className="rounded-xl border border-cyber-border/60 bg-white/[0.03] p-4">
            <div className="text-xs text-slate-400">Security Score</div>
            <div className="mt-2 flex items-end gap-2">
              <span className="text-3xl font-bold text-emerald-400">82</span>
              <span className="mb-1 text-xs text-emerald-400/80">/ 100</span>
            </div>
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/10">
              <div className="h-full w-[82%] rounded-full bg-gradient-to-r from-emerald-400 to-accent-cyan" />
            </div>
          </div>
          <div className="rounded-xl border border-cyber-border/60 bg-white/[0.03] p-4 sm:col-span-2">
            <div className="mb-3 text-xs text-slate-400">Findings by severity</div>
            <div className="space-y-2.5">
              {bars.map((b) => (
                <div key={b.label} className="flex items-center gap-3">
                  <span className="w-16 text-xs text-slate-400">{b.label}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/10">
                    <div className={`h-full rounded-full ${b.c}`} style={{ width: b.w }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="rounded-xl border border-cyber-border/60 bg-white/[0.03] p-4 sm:col-span-3">
            <div className="flex flex-wrap items-center gap-2">
              {["subfinder", "httpx", "naabu", "nmap", "nuclei"].map((tool, i) => (
                <span
                  key={tool}
                  className="rounded-md border border-accent-cyan/20 bg-accent-cyan/10 px-2.5 py-1 font-mono text-xs text-accent-cyan"
                  style={{ opacity: 1 - i * 0.08 }}
                >
                  {tool}
                </span>
              ))}
              <span className="ms-auto flex items-center gap-1.5 text-xs text-emerald-400">
                <span className="h-1.5 w-1.5 animate-pulse-slow rounded-full bg-emerald-400" />
                pipeline running
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
