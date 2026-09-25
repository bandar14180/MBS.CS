"use client";

import { use } from "react";

import { VulnerabilitiesTab } from "@/components/project/VulnerabilitiesTab";

export default function ProjectVulnerabilitiesPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <VulnerabilitiesTab projectId={id} />;
}
