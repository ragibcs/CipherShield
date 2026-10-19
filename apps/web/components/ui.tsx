"use client";

import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Loader2, XCircle } from "lucide-react";

/* ------------------------------- primitives ------------------------------ */

export function Card({
  title,
  icon,
  actions,
  children,
  className = "",
}: {
  title?: string;
  icon?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-xl border border-zinc-800 bg-zinc-900/60 shadow-lg shadow-black/20 ${className}`}
    >
      {(title ?? actions) && (
        <header className="flex flex-wrap items-center gap-2 border-b border-zinc-800 px-4 py-3">
          {icon}
          {title && <h2 className="text-sm font-semibold text-zinc-200">{title}</h2>}
          {actions && <div className="ml-auto">{actions}</div>}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

type Tone = "ok" | "warn" | "danger" | "info" | "neutral";

const TONES: Record<Tone, string> = {
  ok: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  warn: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  danger: "border-red-500/40 bg-red-500/10 text-red-300",
  info: "border-sky-500/40 bg-sky-500/10 text-sky-300",
  neutral: "border-zinc-700 bg-zinc-800/60 text-zinc-300",
};

/** Status pill: icon + text so meaning never depends on color alone. */
export function Badge({
  tone = "neutral",
  icon,
  children,
}: {
  tone?: Tone;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${TONES[tone]}`}
    >
      {icon}
      {children}
    </span>
  );
}

export function Button({
  variant = "primary",
  loading = false,
  disabled,
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "danger";
  loading?: boolean;
}) {
  const styles = {
    primary:
      "bg-emerald-500 text-black hover:bg-emerald-400 disabled:bg-emerald-500/40",
    ghost:
      "border border-zinc-700 bg-zinc-800/60 text-zinc-200 hover:bg-zinc-700/70",
    danger: "border border-red-500/50 bg-red-500/10 text-red-300 hover:bg-red-500/20",
  }[variant];
  return (
    <button
      {...rest}
      disabled={disabled ?? loading}
      className={`inline-flex items-center justify-center gap-2 rounded-md px-3.5 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-70 ${styles}`}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function StatCard({
  label,
  value,
  hint,
  icon,
  badge,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  icon?: ReactNode;
  badge?: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-zinc-500">
        {icon}
        {label}
      </div>
      <div className="mt-2 flex items-center gap-2 text-2xl font-semibold text-zinc-100">
        {value}
        {badge}
      </div>
      {hint && <p className="mt-1 text-xs text-zinc-500">{hint}</p>}
    </div>
  );
}

/* -------------------------------- states --------------------------------- */

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div
      role="status"
      className="flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/50 px-4 py-6 text-sm text-zinc-400"
    >
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      {label}
    </div>
  );
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200"
    >
      <XCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

export function EmptyBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-dashed border-zinc-700 px-4 py-6 text-sm text-zinc-400">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-zinc-500" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

export function SuccessBox({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-zinc-500">{subtitle}</p>}
      </div>
      {actions}
    </div>
  );
}
