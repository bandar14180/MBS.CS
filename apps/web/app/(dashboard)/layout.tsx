"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/lib/auth";
import { Button, Spinner } from "@/components/ui";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { user, workspaceName, loading, logout } = useAuth();
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
    <div className="flex min-h-screen">
      <aside className="flex w-60 flex-col border-r border-slate-800 bg-slate-900/40 p-4">
        <Link href="/dashboard" className="mb-8 block">
          <div className="text-lg font-semibold text-indigo-400">MBS.SC</div>
          <div className="text-xs text-slate-500">Smart Security</div>
        </Link>
        <nav className="flex-1 space-y-1">
          <Link href="/dashboard" className="block rounded-md px-3 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Projects
          </Link>
        </nav>
        <div className="border-t border-slate-800 pt-4">
          <div className="mb-2 px-1 text-xs text-slate-500">Workspace</div>
          <div className="mb-3 truncate px-1 text-sm text-slate-300">{workspaceName}</div>
          <div className="mb-3 truncate px-1 text-xs text-slate-500">{user.email}</div>
          <Button variant="ghost" className="w-full justify-start" onClick={logout}>
            Sign out
          </Button>
        </div>
      </aside>
      <main className="flex-1 overflow-x-hidden p-8">{children}</main>
    </div>
  );
}
