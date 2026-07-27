"use client";

import Link from "next/link";

import { useTranslation } from "@/lib/i18n";

export function CTASection() {
  const { t } = useTranslation();
  return (
    <section className="relative py-24">
      <div className="mx-auto max-w-5xl px-5">
        <div className="relative overflow-hidden rounded-3xl border border-accent-cyan/25 p-10 text-center sm:p-16">
          <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-accent-cyan/15 via-transparent to-accent-violet/20" />
          <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" />
          <div className="relative">
            <h2 className="mx-auto max-w-2xl text-3xl font-bold tracking-tight text-white sm:text-4xl">
              {t("cta.title")}
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-base text-slate-300">{t("cta.subtitle")}</p>
            <Link
              href="/register"
              className="btn-gradient mt-8 inline-block rounded-xl px-8 py-4 text-sm font-semibold text-white shadow-glow"
            >
              {t("cta.button")}
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
