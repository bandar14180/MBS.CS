"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { notificationApi, type AppNotification } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";

const DOT: Record<string, string> = {
  critical: "bg-rose-500",
  warning: "bg-amber-400",
  info: "bg-accent-cyan",
};

export function NotificationBell() {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState(0);
  const [items, setItems] = useState<AppNotification[] | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  const loadCount = useCallback(async () => {
    try {
      setCount((await notificationApi.unreadCount()).count);
    } catch {}
  }, []);

  useEffect(() => {
    loadCount();
    const id = setInterval(loadCount, 30000);
    return () => clearInterval(id);
  }, [loadCount]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (next) {
      try {
        setItems(await notificationApi.list());
      } catch {
        setItems([]);
      }
    }
  }

  async function markAll() {
    try {
      await notificationApi.markAllRead();
      setCount(0);
      setItems((prev) => prev?.map((n) => ({ ...n, read: true })) ?? prev);
    } catch {}
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={toggle}
        aria-label={t("notifications.title")}
        className="relative flex h-9 w-9 items-center justify-center rounded-lg border border-cyber-border/70 bg-white/5 text-slate-300 transition hover:border-accent-cyan/50 hover:text-white"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
          <path d="M6 9a6 6 0 1112 0c0 5 2 6 2 6H4s2-1 2-6z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
          <path d="M10 20a2 2 0 004 0" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
        {count > 0 && (
          <span className="absolute -end-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-semibold text-white">
            {count > 9 ? "9+" : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute end-0 z-50 mt-2 w-80 overflow-hidden rounded-xl glass-strong shadow-glow-violet">
          <div className="flex items-center justify-between border-b border-cyber-border/60 px-4 py-2.5">
            <span className="text-sm font-semibold text-white">{t("notifications.title")}</span>
            {count > 0 && (
              <button onClick={markAll} className="text-xs text-accent-cyan hover:underline">
                {t("notifications.markAllRead")}
              </button>
            )}
          </div>
          <div className="max-h-96 overflow-y-auto">
            {items === null ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">…</div>
            ) : items.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">{t("notifications.empty")}</div>
            ) : (
              items.map((n) => (
                <div
                  key={n.id}
                  className={`flex gap-3 border-b border-cyber-border/40 px-4 py-3 ${n.read ? "opacity-60" : ""}`}
                >
                  <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${DOT[n.severity] || "bg-slate-500"}`} />
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-slate-100">{n.title}</div>
                    {n.body && <div className="mt-0.5 text-xs text-slate-400">{n.body}</div>}
                    <div className="mt-1 text-[11px] text-slate-500">{new Date(n.created_at).toLocaleString()}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
