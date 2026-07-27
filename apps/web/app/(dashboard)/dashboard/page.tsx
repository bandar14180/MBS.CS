"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { dashboardApi, projectApi, type DashboardSummary, type Project } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Badge, Button, Card, ErrorText, Input, Label, Spinner } from "@/components/ui";

export default function DashboardPage() {
  const { t } = useTranslation();
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
        <h1 className="text-2xl font-semibold text-white">{t("dashboard.overview")}</h1>
        {projects && projects.length > 0 && (
          <Button onClick={() => setShowNew((v) => !v)}>
            {showNew ? t("dashboard.cancel") : t("dashboard.newProject")}
          </Button>
        )}
      </div>

      {showNew && (
        <Card className="mb-6">
          <form onSubmit={create} className="space-y-4">
            <div>
              <Label>{t("dashboard.name")}</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} required autoFocus />
            </div>
            <div>
              <Label>{t("dashboard.descriptionOptional")}</Label>
              <Input value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy}>
              {busy ? `${t("dashboard.createProject")}…` : t("dashboard.createProject")}
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
  const { t } = useTranslation();
  const steps = [
    { n: 1, t: t("dashboard.step1Title"), d: t("dashboard.step1Desc") },
    { n: 2, t: t("dashboard.step2Title"), d: t("dashboard.step2Desc") },
    { n: 3, t: t("dashboard.step3Title"), d: t("dashboard.step3Desc") },
    { n: 4, t: t("dashboard.step4Title"), d: t("dashboard.step4Desc") },
  ];
  return (
    <Card className="text-center">
      <h2 className="text-lg font-medium text-white">{t("dashboard.welcome")}</h2>
      <p className="mx-auto mt-1 max-w-md text-sm text-slate-400">{t("dashboard.emptyIntro")}</p>
      <div className="mx-auto mt-6 grid max-w-2xl gap-3 text-start sm:grid-cols-2">
        {steps.map((s) => (
          <div key={s.n} className="flex gap-3 rounded-xl border border-cyber-border/60 bg-white/[0.02] p-4">
            <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full btn-gradient text-sm font-semibold text-white">
              {s.n}
            </div>
            <div>
              <div className="text-sm font-medium text-white">{s.t}</div>
              <div className="text-xs text-slate-400">{s.d}</div>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-6">
        <Button onClick={onCreate}>{t("dashboard.createFirstProject")}</Button>
      </div>
    </Card>
  );
}

function Stat({ label, value, tone = "" }: { label: string; value: number | string; tone?: string }) {
  return (
    <Card>
      <div className={`text-3xl font-semibold ${tone || "text-white"}`}>{value}</div>
      <div className="mt-1 text-xs uppercase tracking-wide text-slate-500">{label}</div>
    </Card>
  );
}

function StatCards({ summary }: { summary: DashboardSummary }) {
  const { t } = useTranslation();
  const sev = summary.vulnerabilities.by_severity;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t("dashboard.projects")} value={summary.projects} />
        <Stat label={t("dashboard.targets")} value={summary.targets} />
        <Stat
          label={t("dashboard.scansRunning")}
          value={summary.scans.running}
          tone={summary.scans.running > 0 ? "text-sky-400" : "text-white"}
        />
        <Stat
          label={t("dashboard.activeFindings")}
          value={summary.vulnerabilities.active}
          tone={summary.vulnerabilities.active > 0 ? "text-orange-400" : "text-white"}
        />
      </div>
      <Card>
        <div className="mb-3 text-xs uppercase tracking-wide text-slate-500">{t("dashboard.findingsBySeverity")}</div>
        <div className="flex flex-wrap gap-4">
          {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
            <div key={k} className="flex items-center gap-2">
              <Badge kind="severity" value={k} />
              <span className="text-lg font-semibold text-white">{sev[k]}</span>
            </div>
          ))}
          {summary.vulnerabilities.total === 0 && (
            <span className="text-sm text-slate-500">{t("dashboard.noFindings")}</span>
          )}
        </div>
      </Card>
    </div>
  );
}

function RecentScans({ summary }: { summary: DashboardSummary }) {
  const { t } = useTranslation();
  if (summary.recent_scans.length === 0) return null;
  return (
    <div className="mt-8">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">{t("dashboard.recentScans")}</h2>
      <div className="space-y-2">
        {summary.recent_scans.map((s) => (
          <Link key={s.id} href={`/projects/${s.project_id}`}>
            <Card className="flex items-center justify-between gap-3 transition hover:border-accent-cyan/40">
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
  const { t } = useTranslation();
  return (
    <div className="mt-8">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">{t("dashboard.projects")}</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        {projects.map((p) => (
          <Link key={p.id} href={`/projects/${p.id}`}>
            <Card className="h-full transition hover:border-accent-cyan/40">
              <div className="font-medium text-white">{p.name}</div>
              {p.description && <div className="mt-1 text-sm text-slate-400">{p.description}</div>}
              <div className="mt-3 text-xs text-slate-500">
                {p.status} · {new Date(p.created_at).toLocaleDateString()}
              </div>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
