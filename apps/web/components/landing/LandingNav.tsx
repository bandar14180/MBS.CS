"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { useTranslation } from "@/lib/i18n";
import { LanguageSelector } from "@/components/LanguageSelector";
import { Logo } from "@/components/landing/Logo";

export function LandingNav() {
  const { t } = useTranslation();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-40 transition-all duration-300 ${
        scrolled ? "glass-strong shadow-lg" : "bg-transparent"
      }`}
    >
      <nav className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-5 py-4">
        <Link href="/" className="flex items-center gap-2.5">
          <Logo className="h-8 w-8" />
          <span className="text-lg font-semibold tracking-tight text-white">
            MBS<span className="text-accent-cyan">.SC</span>
          </span>
        </Link>

        <div className="hidden items-center gap-8 md:flex">
          <a href="#services" className="text-sm text-slate-300 transition hover:text-white">
            {t("nav.services")}
          </a>
          <a href="#agents" className="text-sm text-slate-300 transition hover:text-white">
            {t("nav.agents")}
          </a>
          <a href="#why" className="text-sm text-slate-300 transition hover:text-white">
            {t("nav.why")}
          </a>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <LanguageSelector />
          <Link
            href="/login"
            className="hidden rounded-lg px-3 py-2 text-sm text-slate-200 transition hover:text-white sm:inline-block"
          >
            {t("nav.signIn")}
          </Link>
          <Link
            href="/register"
            className="btn-gradient rounded-lg px-4 py-2 text-sm font-semibold text-white shadow-glow"
          >
            {t("nav.getStarted")}
          </Link>
        </div>
      </nav>
    </header>
  );
}
