"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  FlaskConical,
  LayoutDashboard,
  ScrollText,
  ShieldCheck,
  Vault,
} from "lucide-react";

const LINKS = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/analyze", label: "Analyze", icon: ShieldCheck },
  { href: "/vault", label: "Vault", icon: Vault },
  { href: "/lab", label: "Security Lab", icon: FlaskConical },
  { href: "/audit", label: "Audit & Eval", icon: ScrollText },
];

export function Nav() {
  const pathname = usePathname();
  return (
    <header className="sticky top-0 z-40 border-b border-zinc-800/80 bg-[#090a0d]/85 backdrop-blur">
      <div className="mx-auto flex w-full max-w-7xl flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
        <Link href="/" className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
            <ShieldCheck className="h-5 w-5" aria-hidden />
          </span>
          <span>
            CipherShield <span className="text-emerald-400">AI</span>
          </span>
        </Link>

        <nav aria-label="Primary" className="ml-auto flex flex-wrap items-center gap-1">
          {LINKS.map(({ href, label, icon: Icon }) => {
            const active =
              href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? "page" : undefined}
                className={`flex items-center gap-1.5 rounded-md px-3 py-2 text-sm transition ${
                  active
                    ? "bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/30"
                    : "text-zinc-400 hover:bg-zinc-800/60 hover:text-zinc-100"
                }`}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {label}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <Activity className="h-3.5 w-3.5 text-emerald-400" aria-hidden />
          local-first boundary
        </div>
      </div>
    </header>
  );
}
