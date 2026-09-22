"use client";

// Shared chrome (back link, title, tab nav) for every stage of a project. Each stage is a
// REAL route (/projects/[id], /scans, /assets, /vulnerabilities, /reports) rather than
// client-only tab state, so every stage is directly linkable/bookmarkable and the browser
// back/forward buttons work as expected. Next.js keeps this layout mounted while navigating
// between its sibling routes, so ProjectProvider's fetch happens once, not per stage.
import { use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { useTranslation } from "@/lib/i18n";
import { Spinner } from "@/components/ui";
import { ProjectProvider, useProject } from "@/components/project/ProjectContext";

const TABS = [
  { segment: "", key: "project.tabTargets" },
  { segment: "scans", key: "project.tabScans" },
  { segment: "assets", key: "project.tabAssets" },
  { segment: "vulnerabilities", key: "project.tabVulnerabilities" },
  // Remediation follows Vulnerabilities: findings are what remediation work is derived FROM,
  // so the reading order matches the workflow order.
  { segment: "remediation", key: "project.tabRemediation" },
  { segment: "risk-assessments", key: "project.tabAssessments" },
  { segment: "reports", key: "project.tabReports" },
] as const;

function ProjectChrome({ projectId, children }: { projectId: string; children: React.ReactNode }) {
  const { t } = useTranslation();
  const pathname = usePathname();
  const { project, error } = useProject();

  const base = `/projects/${projectId}`;
  const activeSegment = pathname === base ? "" : pathname.slice(base.length + 1).split("/")[0];

  if (error) {
    return (
      <div className="mx-auto max-w-5xl">
        <p className="text-sm text-rose-400">{error}</p>
        <Link href="/dashboard" className="text-sm text-accent-cyan hover:underline">
          <span className="flip-rtl inline-block">â†</span> {t("project.back")}
        </Link>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="flex justify-center pt-20">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-5xl">
      <Link href="/dashboard" className="text-sm text-slate-500 hover:text-slate-300">
        <span className="flip-rtl inline-block">â†</span> {t("project.back")}
      </Link>
      <div className="mb-6 mt-2">
        <h1 className="text-2xl font-semibold">{project.name}</h1>
        {project.description && <p className="mt-1 text-sm text-slate-400">{project.description}</p>}
      </div>

      <div className="mb-6 flex gap-1 overflow-x-auto border-b border-cyber-border/60">
        {TABS.map((tb) => (
          <Link
            key={tb.segment}
            href={tb.segment ? `${base}/${tb.segment}` : base}
            className={`-mb-px shrink-0 border-b-2 px-4 py-2 text-sm transition ${
              activeSegment === tb.segment
                ? "border-accent-cyan text-accent-cyan"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t(tb.key)}
          </Link>
        ))}
      </div>

      {children}
    </div>
  );
}

export default function ProjectLayout({ children, params }: { children: React.ReactNode; params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <ProjectProvider projectId={id}>
      <ProjectChrome projectId={id}>{children}</ProjectChrome>
    </ProjectProvider>
  );
}
