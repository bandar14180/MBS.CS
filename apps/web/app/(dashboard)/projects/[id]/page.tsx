"use client";

import { use } from "react";

import { TargetsTab } from "@/components/project/TargetsTab";
import { useProject } from "@/components/project/ProjectContext";

export default function ProjectTargetsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { reloadTargets } = useProject();
  return <TargetsTab projectId={id} onChange={reloadTargets} />;
}
