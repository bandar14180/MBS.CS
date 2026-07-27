"use client";

import Link from "next/link";
import { useState } from "react";

import { useAuth } from "@/lib/auth";
import { useTranslation } from "@/lib/i18n";
import { Button, Card, ErrorText, Input, Label } from "@/components/ui";
import { LanguageSelector } from "@/components/LanguageSelector";
import { Logo } from "@/components/landing/Logo";

export default function LoginPage() {
  const { login } = useAuth();
  const { t } = useTranslation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await login(email, password);
    } catch (err: any) {
      setError(err.message || "Login failed");
      setBusy(false);
    }
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-cyber-bg p-4">
      <div className="pointer-events-none absolute inset-0 bg-grid mask-fade-b" />
      <div className="pointer-events-none absolute inset-0 bg-radial-glow" />
      <div className="absolute end-4 top-4 z-10">
        <LanguageSelector />
      </div>

      <Card className="relative w-full max-w-sm glass-strong">
        <Link href="/" className="mb-6 flex items-center gap-2.5">
          <Logo className="h-9 w-9" />
          <span className="text-xl font-semibold text-white">
            MBS<span className="text-accent-cyan">.SC</span>
          </span>
        </Link>
        <h1 className="text-2xl font-bold text-white">{t("auth.signInTitle")}</h1>
        <p className="mb-6 mt-1 text-sm text-slate-400">{t("auth.signInSubtitle")}</p>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <Label>{t("auth.email")}</Label>
            <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
          </div>
          <div>
            <Label>{t("auth.password")}</Label>
            <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <ErrorText>{error}</ErrorText>
          <Button type="submit" disabled={busy} className="w-full">
            {busy ? `${t("auth.signIn")}…` : t("auth.signIn")}
          </Button>
        </form>
        <p className="mt-5 text-center text-sm text-slate-500">
          {t("auth.noAccount")}{" "}
          <Link href="/register" className="text-accent-cyan hover:underline">
            {t("auth.register")}
          </Link>
        </p>
      </Card>
    </main>
  );
}
