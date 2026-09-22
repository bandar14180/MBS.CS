"use client";

import { forwardRef } from "react";

export function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost" }) {
  const styles: Record<string, string> = {
    primary: "btn-gradient text-white shadow-glow",
    secondary: "border border-cyber-border bg-white/5 text-slate-100 hover:border-accent-cyan/40 hover:bg-white/10",
    danger: "bg-rose-600 hover:bg-rose-500 text-white",
    ghost: "bg-transparent text-slate-300 hover:bg-white/5",
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className = "", ...props }, ref) {
    return (
      <input
        ref={ref}
        className={`w-full rounded-lg border border-cyber-border bg-white/5 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none transition focus:border-accent-cyan/50 ${className}`}
        {...props}
      />
    );
  }
);

export function Select({ className = "", children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`rounded-lg border border-cyber-border bg-cyber-panel px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-accent-cyan/50 ${className}`}
      {...props}
    >
      {children}
    </select>
  );
}

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`rounded-2xl border border-cyber-border/60 bg-cyber-panel/50 p-5 ${className}`}>{children}</div>;
}

// FE-9: accepts the native <label> attributes -- `htmlFor` above all -- so a label can be
// programmatically associated with its control. Without that association a screen reader
// announces the input as unlabelled, and clicking the text does not focus the field. Existing
// call sites pass only `children` and are unaffected; `className` is merged rather than
// replaced so the shared styling cannot be silently dropped.
export function Label({ className = "", children, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={`mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400 ${className}`}
      {...props}
    >
      {children}
    </label>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-400/15 text-amber-300 border-amber-400/40",
  low: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  info: "bg-white/5 text-slate-300 border-cyber-border",
};
const STATUS_STYLES: Record<string, string> = {
  open: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  confirmed: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  reopened: "bg-amber-400/15 text-amber-300 border-amber-400/40",
  fixed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  false_positive: "bg-white/5 text-slate-400 border-cyber-border",
  accepted_risk: "bg-white/5 text-slate-400 border-cyber-border",
  completed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  completed_with_errors: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  // A tool run that exited non-zero but still produced usable output. Amber, matching
  // `completed_with_errors`: the run it rolls up into is exactly that, and neither is a
  // failure. Without this entry a `partial` badge fell back to the neutral default.
  partial: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  running: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  queued: "bg-white/5 text-slate-300 border-cyber-border",
  failed: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  verified: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  cancelled: "bg-white/5 text-slate-400 border-cyber-border",
  // --- remediation workflow statuses -------------------------------------------------------
  // Colour encodes how much outstanding WORK a state represents, not severity: outstanding
  // work warms toward amber, finished work is green, and a decision-not-to-fix (risk_accepted,
  // rejected) is neutral so it never reads as "resolved".
  proposed: "bg-white/5 text-slate-300 border-cyber-border",
  in_progress: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  awaiting_verification: "bg-amber-400/15 text-amber-300 border-amber-400/40",
  closed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  risk_accepted: "bg-white/5 text-slate-400 border-cyber-border",
  rejected: "bg-white/5 text-slate-400 border-cyber-border",
  // --- risk acceptance / assessment lifecycle -----------------------------------------------
  active: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  expired: "bg-amber-400/15 text-amber-300 border-amber-400/40",
  revoked: "bg-white/5 text-slate-400 border-cyber-border",
  draft: "bg-white/5 text-slate-300 border-cyber-border",
  issued: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  passed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  // `accepted` is a remediation state (work accepted onto the plan). Deliberately NOT the same
  // styling as `accepted_risk`, which is a decision NOT to fix -- conflating them in the UI
  // would blur exactly the distinction the two statuses exist to draw.
  accepted: "bg-indigo-500/15 text-indigo-300 border-indigo-500/40",
};

export function Badge({ kind, value }: { kind: "severity" | "status"; value: string }) {
  const map = kind === "severity" ? SEVERITY_STYLES : STATUS_STYLES;
  const style = map[value] || "bg-white/5 text-slate-300 border-cyber-border";
  return (
    <span className={`inline-block rounded-md border px-2 py-0.5 text-xs font-medium ${style}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-block h-4 w-4 animate-spin rounded-full border-2 border-cyber-border border-t-accent-cyan ${className}`}
    />
  );
}

export function ErrorText({ children }: { children: React.ReactNode }) {
  if (!children) return null;
  return <p className="text-sm text-rose-400">{children}</p>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-8 text-center text-sm text-slate-500">{children}</p>;
}
