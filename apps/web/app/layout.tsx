import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { I18nProvider } from "@/lib/i18n";

export const metadata: Metadata = {
  title: "MBS.SC — Autonomous AI Cybersecurity",
  description:
    "Autonomous AI agents for next-generation cybersecurity. Discover vulnerabilities, analyze risk, and automate penetration testing.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // lang/dir are managed client-side by I18nProvider; suppress the hydration
  // warning since the server always renders the default (en/ltr).
  return (
    <html lang="en" dir="ltr" suppressHydrationWarning>
      <body className="min-h-screen bg-cyber-bg text-slate-100 antialiased">
        <I18nProvider>
          <AuthProvider>{children}</AuthProvider>
        </I18nProvider>
      </body>
    </html>
  );
}
