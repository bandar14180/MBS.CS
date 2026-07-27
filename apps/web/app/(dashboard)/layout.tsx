"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/lib/auth";
import { useTranslation } from "@/lib/i18n";
import { Button, Spinner } from "@/components/ui";
import { AssistantProvider } from "@/components/assistant/AssistantWidget";
import { LanguageSelector } from "@/components/LanguageSelector";
import { Logo } from "@/components/landing/Logo";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, workspaceName, loading, logout } = useAuth();
  const { t } = useTranslation();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.replace("/login");
  }, [loading, user, router]);

  if (loading || !user) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <Spinner className="h-6 w-6" />
      </main>
    );
  }

  return (
    <AssistantProvider>
      <div className="flex min-h-screen">
        <aside className="flex w-60 flex-col border-e border-cyber-border/60 bg-cyber-panel/40 p-4">
          <Link href="/dashboard" className="mb-8 flex items-center gap-2.5">
            <Logo className="h-8 w-8" />
            <span className="text-lg font-semibold text-white">
              MBS<span className="text-accent-cyan">.SC</span>
            </span>
          </Link>
          <nav className="flex-1 space-y-1">
            <Link href="/dashboard" className="block rounded-lg px-3 py-2 text-sm text-slate-300 transition hover:bg-white/5">
              {t("dashboard.projects")}
            </Link>
            <Link href="/" className="block rounded-lg px-3 py-2 text-sm text-slate-400 transition hover:bg-white/5">
              {t("dashboard.home")}
            </Link>
          </nav>
          <div className="space-y-3 border-t border-cyber-border/60 pt-4">
            <LanguageSelector />
            <div>
              <div className="mb-1 px-1 text-xs text-slate-500">{t("dashboard.workspace")}</div>
              <div className="truncate px-1 text-sm text-slate-300">{workspaceName}</div>
              <div className="truncate px-1 text-xs text-slate-500">{user.email}</div>
            </div>
            <Button variant="ghost" className="w-full justify-start" onClick={logout}>
              {t("dashboard.signOut")}
            </Button>
          </div>
        </aside>
        <main className="flex-1 overflow-x-hidden p-8">{children}</main>
      </div>
    </AssistantProvider>
  );
}
