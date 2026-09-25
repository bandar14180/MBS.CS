"use client";

import { use } from "react";

import { AssessmentsTab } from "@/components/project/AssessmentsTab";

export default function ProjectRiskAssessmentsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <AssessmentsTab projectId={id} />;
}
