"use client";

import { useCallback, useEffect, useState } from "react";

import { ApiError, projectApi, type AuthorizationScope, type Target } from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Badge, Button, Card, Empty, ErrorText, Input, Label, Select, Spinner } from "@/components/ui";

const CRITICALITY = ["low", "medium", "high", "critical"];
const TARGET_TYPES = ["domain", "ip_range", "api", "cloud_account", "repo"];
const PROOF_TYPES = ["dns_txt", "file_upload", "signed_letter", "cloud_iam_role"];

export function TargetsTab({ projectId }: { projectId: string }) {
  const { t: tr } = useTranslation();
  const [targets, setTargets] = useState<Target[] | null>(null);
  const [scopes, setScopes] = useState<Record<string, AuthorizationScope | null>>({});
  const [error, setError] = useState("");

  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [criticality, setCriticality] = useState("medium");
  const [busy, setBusy] = useState(false);

  const loadScope = useCallback(
    async (tid: string) => {
      try {
        const s = await projectApi.getScope(projectId, tid);
        setScopes((p) => ({ ...p, [tid]: s }));
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) setScopes((p) => ({ ...p, [tid]: null }));
      }
    },
    [projectId]
  );

  const load = useCallback(async () => {
    try {
      const t = await projectApi.targets(projectId);
      setTargets(t);
      t.forEach((tg) => loadScope(tg.id));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId, loadScope]);

  useEffect(() => {
    load();
  }, [load]);

  async function addTarget(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await projectApi.addTarget(projectId, type, value, criticality);
      setValue("");
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <h3 className="mb-3 font-medium">{tr("targets.addTarget")}</h3>
        <form onSubmit={addTarget} className="flex flex-wrap items-end gap-3">
          <div>
            <Label>{tr("targets.type")}</Label>
            <Select value={type} onChange={(e) => setType(e.target.value)} dir="ltr">
              {TARGET_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </Select>
          </div>
          <div className="min-w-[16rem] flex-1">
            <Label>{tr("targets.value")}</Label>
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="example.com" required dir="ltr" />
          </div>
          <div>
            <Label>{tr("targets.criticality")}</Label>
            <Select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
              {CRITICALITY.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </div>
          <Button type="submit" disabled={busy}>
            {tr("targets.add")}
          </Button>
        </form>
      </Card>

      <ErrorText>{error}</ErrorText>

      {targets === null ? (
        <Spinner />
      ) : targets.length === 0 ? (
        <Empty>{tr("targets.empty")}</Empty>
      ) : (
        <div className="space-y-3">
          {targets.map((t) => (
            <TargetRow
              key={t.id}
              projectId={projectId}
              target={t}
              scope={scopes[t.id]}
              onChange={() => {
                loadScope(t.id);
                load();
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function TargetRow({
  projectId,
  target,
  scope,
  onChange,
}: {
  projectId: string;
  target: Target;
  scope: AuthorizationScope | null | undefined;
  onChange: () => void;
}) {
  const { t: tr } = useTranslation();
  const [proofType, setProofType] = useState("dns_txt");
  const [proofRef, setProofRef] = useState("");
  const [activeAllowed, setActiveAllowed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submitProof() {
    setBusy(true);
    setErr("");
    try {
      await projectApi.submitScope(projectId, target.id, proofType, proofRef || "mbs-verify");
      onChange();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function verify() {
    setBusy(true);
    setErr("");
    try {
      await projectApi.verifyScope(projectId, target.id, activeAllowed);
      onChange();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function setCrit(c: string) {
    try {
      await projectApi.setCriticality(projectId, target.id, c);
      onChange();
    } catch {}
  }

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-mono text-sm text-slate-100" dir="ltr">{target.value}</div>
          <div className="text-xs text-slate-500" dir="ltr">{target.type}</div>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500">{tr("targets.criticality")}</span>
            <Select value={target.criticality} onChange={(e) => setCrit(e.target.value)}>
              {CRITICALITY.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </div>
          {scope === undefined ? (
            <Spinner />
          ) : scope === null ? (
            <span className="text-xs text-slate-500">{tr("targets.noScope")}</span>
          ) : scope.verified ? (
            <span className="flex items-center gap-2">
              <Badge kind="status" value="verified" />
              <span className="text-xs text-slate-500">
                {tr("targets.activeTesting")}: {scope.active_testing_allowed ? tr("targets.yes") : tr("targets.no")}
              </span>
            </span>
          ) : (
            <span className="text-xs text-amber-400">{tr("targets.submittedNotVerified")}</span>
          )}
        </div>
      </div>

      {(scope === null || (scope && !scope.verified)) && (
        <div className="mt-4 border-t border-slate-800 pt-4">
          {scope === null ? (
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <Label>{tr("targets.proofType")}</Label>
                <Select value={proofType} onChange={(e) => setProofType(e.target.value)} dir="ltr">
                  {PROOF_TYPES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="min-w-[14rem] flex-1">
                <Label>{tr("targets.proofReference")}</Label>
                <Input value={proofRef} onChange={(e) => setProofRef(e.target.value)} placeholder="mbs-verify=..." dir="ltr" />
              </div>
              <Button variant="secondary" onClick={submitProof} disabled={busy}>
                {tr("targets.submitProof")}
              </Button>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-4">
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={activeAllowed} onChange={(e) => setActiveAllowed(e.target.checked)} />
                {tr("targets.allowActive")}
              </label>
              <Button onClick={verify} disabled={busy}>
                {tr("targets.verify")}
              </Button>
            </div>
          )}
          <ErrorText>{err}</ErrorText>
        </div>
      )}
    </Card>
  );
}
