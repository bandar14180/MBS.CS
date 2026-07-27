"use client";

import Link from "next/link";

import { useTranslation } from "@/lib/i18n";
import { Logo } from "@/components/landing/Logo";

export function Footer() {
  const { t } = useTranslation();
  const year = new Date().getFullYear();
  return (
    <footer className="border-t border-cyber-border/60 py-12">
      <div className="mx-auto max-w-7xl px-5">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-4">
          <div className="lg:col-span-2">
            <div className="flex items-center gap-2.5">
              <Logo className="h-8 w-8" />
              <span className="text-lg font-semibold text-white">
                MBS<span className="text-accent-cyan">.SC</span>
              </span>
            </div>
            <p className="mt-4 max-w-sm text-sm text-slate-400">{t("footer.tagline")}</p>
          </div>

          <div>
            <div className="text-sm font-semibold text-white">{t("footer.product")}</div>
            <ul className="mt-4 space-y-2 text-sm text-slate-400">
              <li><a href="#services" className="transition hover:text-white">{t("footer.services")}</a></li>
              <li><a href="#agents" className="transition hover:text-white">{t("footer.agents")}</a></li>
              <li><Link href="/dashboard" className="transition hover:text-white">{t("footer.dashboard")}</Link></li>
              <li><a href="#why" className="transition hover:text-white">{t("footer.security")}</a></li>
            </ul>
          </div>

          <div>
            <div className="text-sm font-semibold text-white">{t("footer.company")}</div>
            <ul className="mt-4 space-y-2 text-sm text-slate-400">
              <li><span className="cursor-default">{t("footer.about")}</span></li>
              <li><span className="cursor-default">{t("footer.contact")}</span></li>
              <li><span className="cursor-default">{t("footer.docs")}</span></li>
            </ul>
          </div>
        </div>

        <div className="mt-10 border-t border-cyber-border/50 pt-6 text-center text-xs text-slate-500">
          © {year} MBS.SC — {t("footer.rights")}
        </div>
      </div>
    </footer>
  );
}
