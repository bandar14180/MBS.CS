"use client";

// Shared project chrome state (project details + target list), fetched once by the
// layout and reused by every stage page underneath it -- Next.js keeps a layout mounted
// while navigating between its sibling routes, so this context survives switching between
// Targets/Scans/Assets/Vulnerabilities/Reports without a re-fetch on every click.
import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { projectApi, type Project, type Target } from "@/lib/api";

interface ProjectContextValue {
  project: Project | null;
  targets: Target[];
  error: string;
  reloadTargets: () => void;
}

const ProjectContext = createContext<ProjectContextValue | null>(null);

export function ProjectProvider({ projectId, children }: { projectId: string; children: React.ReactNode }) {
  const [project, setProject] = useState<Project | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [error, setError] = useState("");

  const reloadTargets = useCallback(() => {
    projectApi.targets(projectId).then(setTargets).catch(() => {});
  }, [projectId]);

  useEffect(() => {
    projectApi.get(projectId).then(setProject).catch((e) => setError(e.message));
    reloadTargets();
  }, [projectId, reloadTargets]);

  return (
    <ProjectContext.Provider value={{ project, targets, error, reloadTargets }}>{children}</ProjectContext.Provider>
  );
}

export function useProject(): ProjectContextValue {
  const ctx = useContext(ProjectContext);
  if (!ctx) throw new Error("useProject must be used within <ProjectProvider>");
  return ctx;
}
