import type { Metadata } from "next";
import "./globals.css";
import { Nav } from "@/components/nav";

export const metadata: Metadata = {
  title: {
    default: "CipherShield AI",
    template: "%s · CipherShield AI",
  },
  description:
    "Local-first secret-isolating gateway for LLM-powered security analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-emerald-500 focus:px-3 focus:py-2 focus:text-black"
        >
          Skip to content
        </a>
        <div className="min-h-screen">
          <Nav />
          <main id="main" className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
