"use client";

import { use } from "react";

import { ScansTab } from "@/components/project/ScansTab";
import { useProject } from "@/components/project/ProjectContext";

export default function ProjectScansPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { targets } = useProject();
  return <ScansTab projectId={id} targets={targets} />;
}
