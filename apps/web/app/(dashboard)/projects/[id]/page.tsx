"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { projectApi, type Project, type Target } from "@/lib/api";
import { Spinner } from "@/components/ui";
import { TargetsTab } from "@/components/project/TargetsTab";
import { ScansTab } from "@/components/project/ScansTab";
import { VulnerabilitiesTab } from "@/components/project/VulnerabilitiesTab";
import { ReportsTab } from "@/components/project/ReportsTab";

const TABS = ["Targets", "Scans", "Vulnerabilities", "Reports"] as const;
type Tab = (typeof TABS)[number];

export default function ProjectPage({ params }: { params: { id: string } }) {
  const projectId = params.id;
  const [project, setProject] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [tab, setTab] = useState<Tab>("Targets");
  const [error, setError] = useState("");

  const loadTargets = useCallback(() => {
    projectApi.targets(projectId).then(setTargets).catch(() => {});
  }, [projectId]);

  useEffect(() => {
    projectApi.get(projectId).then(setProject).catch((e) => setError(e.message));
    loadTargets();
  }, [projectId, loadTargets]);

  if (error) {
    return (
      <div className="mx-auto max-w-5xl">
        <p className="text-sm text-rose-400">{error}</p>
        <Link href="/dashboard" className="text-sm text-indigo-400 hover:underline">
          ← Back to projects
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
        ← Projects
      </Link>
      <div className="mb-6 mt-2">
        <h1 className="text-2xl font-semibold">{project.name}</h1>
        {project.description && <p className="mt-1 text-sm text-slate-400">{project.description}</p>}
      </div>

      <div className="mb-6 flex gap-1 border-b border-slate-800">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-4 py-2 text-sm transition ${
              tab === t
                ? "border-indigo-500 text-indigo-400"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Targets" && <TargetsTab projectId={projectId} />}
      {tab === "Scans" && <ScansTab projectId={projectId} targets={targets} />}
      {tab === "Vulnerabilities" && <VulnerabilitiesTab projectId={projectId} />}
      {tab === "Reports" && <ReportsTab projectId={projectId} />}
    </div>
  );
}
