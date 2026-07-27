"use client";

// Lightweight, dependency-free i18n for the App Router. Dictionaries are plain
// JSON files (one per language) under /locales, so adding a language is: drop a
// file in, register it in LOCALES below. English is the global default; Arabic
// renders full RTL. Locale persists in localStorage and drives <html lang/dir>.
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

import en from "@/locales/en.json";
import ar from "@/locales/ar.json";
import ms from "@/locales/ms.json";
import fr from "@/locales/fr.json";
import pt from "@/locales/pt.json";
import it from "@/locales/it.json";
import es from "@/locales/es.json";

export type Locale = "en" | "ar" | "ms" | "fr" | "pt" | "it" | "es";

type Dict = Record<string, unknown>;

export const LOCALES: { code: Locale; label: string; native: string; dir: "ltr" | "rtl"; flag: string }[] = [
  { code: "en", label: "English", native: "English", dir: "ltr", flag: "🇬🇧" },
  { code: "ar", label: "Arabic", native: "العربية", dir: "rtl", flag: "🇸🇦" },
  { code: "ms", label: "Malay", native: "Bahasa Melayu", dir: "ltr", flag: "🇲🇾" },
  { code: "fr", label: "French", native: "Français", dir: "ltr", flag: "🇫🇷" },
  { code: "pt", label: "Portuguese", native: "Português", dir: "ltr", flag: "🇵🇹" },
  { code: "it", label: "Italian", native: "Italiano", dir: "ltr", flag: "🇮🇹" },
  { code: "es", label: "Spanish", native: "Español", dir: "ltr", flag: "🇪🇸" },
];

const DICTS: Record<Locale, Dict> = { en, ar, ms, fr, pt, it, es } as Record<Locale, Dict>;
const DEFAULT_LOCALE: Locale = "en";
const STORAGE_KEY = "mbs_locale";

function dirFor(locale: Locale): "ltr" | "rtl" {
  return LOCALES.find((l) => l.code === locale)?.dir ?? "ltr";
}

// Resolve a dotted key ("hero.title") against a dictionary, falling back to
// English, then to the raw key so a missing string is visible but never crashes.
function resolve(dict: Dict, key: string): string | undefined {
  return key.split(".").reduce<unknown>((acc, part) => {
    if (acc && typeof acc === "object" && part in (acc as Dict)) return (acc as Dict)[part];
    return undefined;
  }, dict) as string | undefined;
}

interface I18nContextValue {
  locale: Locale;
  dir: "ltr" | "rtl";
  setLocale: (l: Locale) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  // Hydrate the saved locale on mount (client-only; SSR always renders default).
  useEffect(() => {
    const saved = (typeof window !== "undefined" && localStorage.getItem(STORAGE_KEY)) as Locale | null;
    if (saved && DICTS[saved]) setLocaleState(saved);
  }, []);

  // Keep <html lang/dir> in sync so RTL, fonts, and a11y are correct globally.
  useEffect(() => {
    if (typeof document === "undefined") return;
    document.documentElement.lang = locale;
    document.documentElement.dir = dirFor(locale);
  }, [locale]);

  const setLocale = useCallback((l: Locale) => {
    if (!DICTS[l]) return;
    setLocaleState(l);
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, l);
  }, []);

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>) => {
      const raw = resolve(DICTS[locale], key) ?? resolve(DICTS[DEFAULT_LOCALE], key) ?? key;
      if (typeof raw !== "string") return key;
      if (!vars) return raw;
      return raw.replace(/\{(\w+)\}/g, (_, name) => String(vars[name] ?? `{${name}}`));
    },
    [locale]
  );

  const value = useMemo<I18nContextValue>(() => ({ locale, dir: dirFor(locale), setLocale, t }), [locale, setLocale, t]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useTranslation(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useTranslation must be used within <I18nProvider>");
  return ctx;
}

// Convenience for reading a whole array/object subtree (e.g. list items) with
// the same English fallback semantics as t().
export function useDict() {
  const { locale } = useTranslation();
  return useCallback(
    <T,>(key: string): T | undefined => {
      return (resolve(DICTS[locale], key) ?? resolve(DICTS[DEFAULT_LOCALE], key)) as T | undefined;
    },
    [locale]
  );
}
