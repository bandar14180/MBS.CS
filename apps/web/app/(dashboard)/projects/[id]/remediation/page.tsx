"use client";

import { use } from "react";

import { RemediationTab } from "@/components/project/RemediationTab";

export default function ProjectRemediationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <RemediationTab projectId={id} />;
}
