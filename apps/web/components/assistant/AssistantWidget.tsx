"use client";

import { createContext, useCallback, useContext, useRef, useState } from "react";

import { ApiError, assistantApi } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";

interface Grounding {
  projectId?: string;
  vulnerabilityId?: string;
  label?: string;
}
interface AssistantContextValue {
  open: (grounding?: Grounding) => void;
}
const AssistantContext = createContext<AssistantContextValue | null>(null);

export function useAssistant(): AssistantContextValue {
  const ctx = useContext(AssistantContext);
  if (!ctx) throw new Error("useAssistant must be used within <AssistantProvider>");
  return ctx;
}

interface Msg {
  role: "user" | "assistant";
  text: string;
}

export function AssistantProvider({ children }: { children: React.ReactNode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [grounding, setGrounding] = useState<Grounding | null>(null);

  const open = useCallback((g?: Grounding) => {
    if (g) setGrounding(g);
    setIsOpen(true);
  }, []);

  return (
    <AssistantContext.Provider value={{ open }}>
      {children}
      {!isOpen && <LauncherButton onClick={() => setIsOpen(true)} />}
      {isOpen && <ChatPanel grounding={grounding} onClose={() => setIsOpen(false)} onClearGrounding={() => setGrounding(null)} />}
    </AssistantContext.Provider>
  );
}

function LauncherButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-label="Open Security Assistant"
      className="btn-gradient fixed bottom-6 end-6 z-40 flex h-14 w-14 items-center justify-center rounded-full text-white shadow-glow"
    >
      <SparkIcon className="h-6 w-6" />
    </button>
  );
}

function ChatPanel({
  grounding,
  onClose,
  onClearGrounding,
}: {
  grounding: Grounding | null;
  onClose: () => void;
  onClearGrounding: () => void;
}) {
  const { t } = useTranslation();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  const scrollDown = () => requestAnimationFrame(() => listRef.current?.scrollTo(0, listRef.current.scrollHeight));

  const send = useCallback(
    async (question: string) => {
      const q = question.trim();
      if (q.length < 3 || busy) return;
      setMessages((m) => [...m, { role: "user", text: q }]);
      setInput("");
      setBusy(true);
      scrollDown();
      try {
        const res = await assistantApi.ask(q, {
          projectId: grounding?.projectId,
          vulnerabilityId: grounding?.vulnerabilityId,
        });
        setMessages((m) => [...m, { role: "assistant", text: res.answer || t("assistant.error") }]);
      } catch (e) {
        const text = e instanceof ApiError && e.status === 503 ? t("assistant.unavailable") : t("assistant.error");
        setMessages((m) => [...m, { role: "assistant", text }]);
      } finally {
        setBusy(false);
        scrollDown();
      }
    },
    [busy, grounding, t]
  );

  const suggestions = grounding?.vulnerabilityId
    ? [t("assistant.suggest1"), t("assistant.suggest2"), t("assistant.suggest3")]
    : [];

  return (
    <div className="fixed bottom-6 end-6 z-50 flex h-[32rem] w-[calc(100vw-3rem)] max-w-sm flex-col overflow-hidden rounded-2xl glass-strong shadow-glow-violet">
      {/* header */}
      <div className="flex items-center gap-3 border-b border-cyber-border/60 px-4 py-3">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent-violet/20 text-accent-violet">
          <SparkIcon className="h-4 w-4" />
        </span>
        <div className="flex-1">
          <div className="text-sm font-semibold text-white">{t("assistant.title")}</div>
          <div className="text-xs text-slate-400">{t("assistant.subtitle")}</div>
        </div>
        <button onClick={onClose} aria-label="Close" className="text-slate-400 transition hover:text-white">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" /></svg>
        </button>
      </div>

      {grounding?.label && (
        <div className="flex items-center justify-between gap-2 border-b border-cyber-border/40 bg-accent-cyan/5 px-4 py-2">
          <span className="truncate text-xs text-accent-cyan">{t("assistant.grounded", { title: grounding.label })}</span>
          <button onClick={onClearGrounding} className="shrink-0 text-xs text-slate-500 hover:text-slate-300">✕</button>
        </div>
      )}

      {/* messages */}
      <div ref={listRef} className="flex-1 space-y-3 overflow-y-auto px-4 py-4">
        {messages.length === 0 && <p className="mt-6 text-center text-sm text-slate-500">{t("assistant.empty")}</p>}
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] whitespace-pre-wrap rounded-2xl px-3.5 py-2.5 text-sm ${
                m.role === "user"
                  ? "bg-brand-600 text-white"
                  : "border border-cyber-border/60 bg-white/[0.04] text-slate-200"
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}
        {busy && (
          <div className="flex justify-start">
            <div className="rounded-2xl border border-cyber-border/60 bg-white/[0.04] px-3.5 py-2.5 text-sm text-slate-400">
              <span className="inline-flex gap-1">
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-accent-cyan" style={{ animationDelay: "0ms" }} />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-accent-cyan" style={{ animationDelay: "150ms" }} />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-accent-cyan" style={{ animationDelay: "300ms" }} />
              </span>
            </div>
          </div>
        )}
      </div>

      {/* suggestions */}
      {suggestions.length > 0 && messages.length === 0 && (
        <div className="flex flex-wrap gap-2 px-4 pb-2">
          {suggestions.map((s) => (
            <button
              key={s}
              onClick={() => send(s)}
              className="rounded-full border border-accent-cyan/25 bg-accent-cyan/10 px-3 py-1 text-xs text-accent-cyan transition hover:bg-accent-cyan/20"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
        className="flex items-center gap-2 border-t border-cyber-border/60 p-3"
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={t("assistant.placeholder")}
          className="flex-1 rounded-lg border border-cyber-border bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none focus:border-accent-cyan/50"
        />
        <button
          type="submit"
          disabled={busy || input.trim().length < 3}
          className="btn-gradient rounded-lg px-3 py-2 text-white disabled:opacity-40"
          aria-label={t("assistant.send")}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" className="flip-rtl"><path d="M4 12l16-8-6 8 6 8-16-8z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" /></svg>
        </button>
      </form>
    </div>
  );
}

function SparkIcon({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z" fill="currentColor" />
      <circle cx="18.5" cy="18.5" r="1.5" fill="currentColor" />
    </svg>
  );
}
