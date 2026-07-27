"use client";

import { useEffect, useRef, useState } from "react";

import { LOCALES, useTranslation, type Locale } from "@/lib/i18n";

export function LanguageSelector({ compact = false }: { compact?: boolean }) {
  const { locale, setLocale } = useTranslation();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const current = LOCALES.find((l) => l.code === locale) ?? LOCALES[0];

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  function pick(code: Locale) {
    setLocale(code);
    setOpen(false);
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-label="Select language"
        className="flex items-center gap-2 rounded-lg border border-cyber-border/70 bg-white/5 px-3 py-2 text-sm text-slate-200 transition hover:border-accent-cyan/50 hover:bg-white/10"
      >
        <span className="text-base leading-none">{current.flag}</span>
        {!compact && <span className="hidden sm:inline">{current.native}</span>}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" className={`transition ${open ? "rotate-180" : ""}`}>
          <path d="M6 9l6 6 6-6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open && (
        <div className="absolute end-0 z-50 mt-2 w-48 overflow-hidden rounded-xl glass-strong p-1 shadow-glow-violet">
          {LOCALES.map((l) => (
            <button
              key={l.code}
              onClick={() => pick(l.code)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-start text-sm transition ${
                l.code === locale ? "bg-accent-cyan/15 text-white" : "text-slate-300 hover:bg-white/5"
              }`}
            >
              <span className="text-base leading-none">{l.flag}</span>
              <span className="flex-1">{l.native}</span>
              {l.code === locale && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                  <path d="M20 6L9 17l-5-5" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
