"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { dashboardApi, projectApi, type DashboardSummary, type Project } from "@/lib/api";
import { Badge, Button, Card, ErrorText, Input, Label, Spinner } from "@/components/ui";

export default function DashboardPage() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const [s, p] = await Promise.all([dashboardApi.summary(), projectApi.list()]);
      setSummary(s);
      setProjects(p);
    } catch (e: any) {
      setError(e.message);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await projectApi.create(name, description || undefined);
      setName("");
      setDescription("");
      setShowNew(false);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const loading = summary === null || projects === null;

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Overview</h1>
        {projects && projects.length > 0 && (
          <Button onClick={() => setShowNew((v) => !v)}>{showNew ? "Cancel" : "New project"}</Button>
        )}
      </div>

      {showNew && (
        <Card className="mb-6">
          <form onSubmit={create} className="space-y-4">
            <div>
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
            </div>
            <div>
              <Label>Description (optional)</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy}>
              {busy ? "Creating…" : "Create project"}
            </Button>
          </form>
        </Card>
      )}

      <ErrorText>{error}</ErrorText>

      {loading ? (
        <Spinner />
      ) : projects.length === 0 ? (
        <EmptyState onCreate={() => setShowNew(true)} />
      ) : (
        <>
          <StatCards summary={summary!} />
          <RecentScans summary={summary!} />
          <ProjectsGrid projects={projects} />
        </>
      )}
    </div>
  );
}

function EmptyState({ onCreate }: { onCreate: () => void }) {
  const steps = [
    { n: 1, t: "Create a project", d: "A workspace for a target and its scans." },
    { n: 2, t: "Add & verify a target", d: "Prove ownership before any tool runs — a hard gate." },
    { n: 3, t: "Run a scan", d: "Pick tools (subfinder, httpx, nmap, nuclei…) and launch." },
    { n: 4, t: "Review findings", d: "Risk, compliance, remediation, and PDF reports." },
  ];
  return (
    <Card className="text-center">
      <h2 className="text-lg font-medium text-slate-100">Welcome to MBS.SC</h2>
      <p className="mx-auto mt-1 max-w-md text-sm text-slate-400">
        You have no projects yet. Here is how a security assessment flows:
      </p>
      <div className="mx-auto mt-6 grid max-w-2xl gap-3 text-left sm:grid-cols-2">
        {steps.map((s) => (
          <div key={s.n} className="flex gap-3 rounded-md border border-slate-800 bg-slate-900/40 p-4">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-sm font-semibold text-white">
              {s.n}
            </div>
            <div>
              <div className="text-sm font-medium text-slate-100">{s.t}</div>
              <div className="text-xs text-slate-400">{s.d}</div>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-6">
        <Button onClick={onCreate}>Create your first project</Button>
      </div>
    </Card>
  );
}

function Stat({ label, value, tone = "" }: { label: string; value: number | string; tone?: string }) {
  return (
    <Card>
      <div className={`text-3xl font-semibold ${tone || "text-slate-100"}`}>{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">{label}</div>
    </Card>
  );
}

function StatCards({ summary }: { summary: DashboardSummary }) {
  const sev = summary.vulnerabilities.by_severity;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Projects" value={summary.projects} />
        <Stat label="Targets" value={summary.targets} />
        <Stat
          label="Scans running"
          value={summary.scans.running}
          tone={summary.scans.running > 0 ? "text-blue-400" : "text-slate-100"}
        />
        <Stat
          label="Active findings"
          value={summary.vulnerabilities.active}
          tone={summary.vulnerabilities.active > 0 ? "text-orange-400" : "text-slate-100"}
        />
      </div>
      <Card>
        <div className="mb-3 text-xs uppercase tracking-wide text-slate-500">Active findings by severity</div>
        <div className="flex flex-wrap gap-4">
          {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
            <div key={k} className="flex items-center gap-2">
              <Badge kind="severity" value={k} />
              <span className="text-lg font-semibold text-slate-100">{sev[k]}</span>
            </div>
          ))}
          {summary.vulnerabilities.total === 0 && (
            <span className="text-sm text-slate-500">No findings yet — run a scan.</span>
          )}
        </div>
      </Card>
    </div>
  );
}

function RecentScans({ summary }: { summary: DashboardSummary }) {
  if (summary.recent_scans.length === 0) return null;
  return (
    <div className="mt-8">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">Recent scans</h2>
      <div className="space-y-2">
        {summary.recent_scans.map((s) => (
          <Link key={s.id} href={`/projects/${s.project_id}`}>
            <Card className="flex items-center justify-between gap-3 transition hover:border-indigo-700">
              <div className="flex items-center gap-3">
                <Badge kind="status" value={s.status} />
                <span className="font-mono text-sm text-slate-200">{s.target_value}</span>
                <span className="text-xs text-slate-500">{s.project_name}</span>
              </div>
              <span className="text-xs text-slate-500">{new Date(s.created_at).toLocaleString()}</span>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}

function ProjectsGrid({ projects }: { projects: Project[] }) {
  return (
    <div className="mt-8">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">Projects</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        {projects.map((p) => (
          <Link key={p.id} href={`/projects/${p.id}`}>
            <Card className="h-full transition hover:border-indigo-700">
              <div className="font-medium text-slate-100">{p.name}</div>
              {p.description && <div className="mt-1 text-sm text-slate-400">{p.description}</div>}
              <div className="mt-3 text-xs text-slate-500">
                {p.status} · created {new Date(p.created_at).toLocaleDateString()}
              </div>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
