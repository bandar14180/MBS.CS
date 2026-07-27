"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

import { tokens } from "@/lib/api";
import { Spinner } from "@/components/ui";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace(tokens.access ? "/dashboard" : "/login");
  }, [router]);
  return (
    <main className="flex min-h-screen items-center justify-center">
      <Spinner className="h-6 w-6" />
    </main>
  );
}
