"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { projectApi, type Project } from "@/lib/api";
import { Button, Card, Empty, ErrorText, Input, Label, Spinner } from "@/components/ui";

export default function DashboardPage() {
  const [projects, setProjects] = useState<Project[] | null>(null);
  const [error, setError] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setProjects(await projectApi.list());
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

  return (
    <div className="mx-auto max-w-5xl">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Projects</h1>
        <Button onClick={() => setShowNew((v) => !v)}>{showNew ? "Cancel" : "New project"}</Button>
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

      {projects === null ? (
        <Spinner />
      ) : projects.length === 0 ? (
        <Empty>No projects yet. Create one to start scanning.</Empty>
      ) : (
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
      )}
    </div>
  );
}
