"use client";

import { forwardRef } from "react";

export function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "danger" | "ghost" }) {
  const styles: Record<string, string> = {
    primary: "bg-indigo-600 hover:bg-indigo-500 text-white",
    secondary: "bg-slate-700 hover:bg-slate-600 text-slate-100",
    danger: "bg-red-700 hover:bg-red-600 text-white",
    ghost: "bg-transparent hover:bg-slate-800 text-slate-300",
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed ${styles[variant]} ${className}`}
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
        className={`w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-indigo-500 focus:outline-none ${className}`}
        {...props}
      />
    );
  }
);

export function Select({ className = "", children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={`rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-indigo-500 focus:outline-none ${className}`}
      {...props}
    >
      {children}
    </select>
  );
}

export function Card({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={`rounded-lg border border-slate-800 bg-slate-900/60 p-5 ${className}`}>{children}</div>;
}

export function Label({ children }: { children: React.ReactNode }) {
  return <label className="mb-1 block text-xs font-medium uppercase tracking-wide text-slate-400">{children}</label>;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-950 text-red-300 border-red-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  medium: "bg-amber-950 text-amber-300 border-amber-800",
  low: "bg-blue-950 text-blue-300 border-blue-800",
  info: "bg-slate-800 text-slate-300 border-slate-700",
};
const STATUS_STYLES: Record<string, string> = {
  open: "bg-red-950 text-red-300 border-red-800",
  confirmed: "bg-orange-950 text-orange-300 border-orange-800",
  reopened: "bg-amber-950 text-amber-300 border-amber-800",
  fixed: "bg-emerald-950 text-emerald-300 border-emerald-800",
  false_positive: "bg-slate-800 text-slate-400 border-slate-700",
  accepted_risk: "bg-slate-800 text-slate-400 border-slate-700",
  completed: "bg-emerald-950 text-emerald-300 border-emerald-800",
  running: "bg-blue-950 text-blue-300 border-blue-800",
  queued: "bg-slate-800 text-slate-300 border-slate-700",
  failed: "bg-red-950 text-red-300 border-red-800",
  verified: "bg-emerald-950 text-emerald-300 border-emerald-800",
};

export function Badge({ kind, value }: { kind: "severity" | "status"; value: string }) {
  const map = kind === "severity" ? SEVERITY_STYLES : STATUS_STYLES;
  const style = map[value] || "bg-slate-800 text-slate-300 border-slate-700";
  return (
    <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${style}`}>
      {value.replace(/_/g, " ")}
    </span>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <span
      className={`inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-600 border-t-indigo-400 ${className}`}
    />
  );
}

export function ErrorText({ children }: { children: React.ReactNode }) {
  if (!children) return null;
  return <p className="text-sm text-red-400">{children}</p>;
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-8 text-center text-sm text-slate-500">{children}</p>;
}
