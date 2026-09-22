"use client";

import { use } from "react";

import { AssetsTab } from "@/components/project/AssetsTab";

export default function ProjectAssetsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <AssetsTab projectId={id} />;
}
