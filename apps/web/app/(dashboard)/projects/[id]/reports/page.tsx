"use client";

import { use } from "react";

import { ReportsTab } from "@/components/project/ReportsTab";

export default function ProjectReportsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <ReportsTab projectId={id} />;
}
