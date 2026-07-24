import { getHealth } from "@/lib/api-client";

export default async function HomePage() {
  let apiStatus: string;
  try {
    const health = await getHealth();
    apiStatus = `${health.service} — ${health.status} (${health.environment})`;
  } catch {
    apiStatus = "API unreachable";
  }

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
      <h1 className="text-3xl font-semibold">MBS.SC</h1>
      <p className="text-slate-400">Smart Security. Fast Results.</p>
      <p className="rounded-md border border-slate-800 bg-slate-900 px-4 py-2 font-mono text-sm">
        {apiStatus}
      </p>
    </main>
  );
}
