"use client";

import { useCallback, useEffect, useState } from "react";

import {
  vulnApi,
  type ComplianceMapping,
  type Remediation,
  type RiskScore,
  type Vulnerability,
} from "@/lib/api";
import { Badge, Button, Card, Empty, ErrorText, Label, Select, Spinner } from "@/components/ui";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "open", "confirmed", "false_positive", "remediated", "accepted_risk"];
const STATUS_CHOICES = ["confirmed", "false_positive", "remediated", "accepted_risk"];

export function VulnerabilitiesTab({ projectId }: { projectId: string }) {
  const [vulns, setVulns] = useState<Vulnerability[] | null>(null);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setVulns(await vulnApi.list(projectId, severity || undefined, status || undefined));
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId, severity, status]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label>Severity</Label>
            <Select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s || "all"}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label>Status</Label>
            <Select value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.replace("_", " ") : "all"}
                </option>
              ))}
            </Select>
          </div>
        </div>
      </Card>

      <ErrorText>{error}</ErrorText>

      {vulns === null ? (
        <Spinner />
      ) : vulns.length === 0 ? (
        <Empty>No vulnerabilities match. Run a scan to populate findings.</Empty>
      ) : (
        <div className="space-y-3">
          {vulns.map((v) => (
            <Card key={v.id}>
              <button
                className="flex w-full items-center justify-between gap-3 text-left"
                onClick={() => setOpenId(openId === v.id ? null : v.id)}
              >
                <div className="flex items-center gap-3">
                  <Badge kind="severity" value={v.severity} />
                  <div>
                    <div className="font-medium text-slate-100">{v.title}</div>
                    <div className="text-xs text-slate-500">
                      {v.category || "uncategorized"}
                      {v.cvss_score != null && ` · CVSS ${v.cvss_score}`}
                    </div>
                  </div>
                </div>
                <Badge kind="status" value={v.status} />
              </button>
              {openId === v.id && <VulnDetail projectId={projectId} vuln={v} onChange={load} />}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function VulnDetail({
  projectId,
  vuln,
  onChange,
}: {
  projectId: string;
  vuln: Vulnerability;
  onChange: () => void;
}) {
  const [risk, setRisk] = useState<RiskScore | null>(null);
  const [compliance, setCompliance] = useState<ComplianceMapping[]>([]);
  const [remediation, setRemediation] = useState<Remediation | null>(null);
  const [newStatus, setNewStatus] = useState("confirmed");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [genBusy, setGenBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    vulnApi.risk(projectId, vuln.id).then(setRisk).catch(() => {});
    vulnApi.compliance(projectId, vuln.id).then(setCompliance).catch(() => {});
    vulnApi.getRemediation(projectId, vuln.id).then(setRemediation).catch(() => setRemediation(null));
  }, [projectId, vuln.id]);

  async function applyStatus() {
    setBusy(true);
    setErr("");
    try {
      await vulnApi.setStatus(projectId, vuln.id, newStatus, justification || "updated via dashboard");
      onChange();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function genRemediation() {
    setGenBusy(true);
    setErr("");
    try {
      setRemediation(await vulnApi.generateRemediation(projectId, vuln.id));
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setGenBusy(false);
    }
  }

  return (
    <div className="mt-4 space-y-4 border-t border-slate-800 pt-4 text-sm">
      {vuln.description && <p className="text-slate-300">{vuln.description}</p>}

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <div className="mb-1 text-xs uppercase text-slate-500">Risk</div>
          {risk ? (
            <div className="text-slate-300">
              <div className="text-2xl font-semibold text-slate-100">{risk.final_risk_score ?? "—"}</div>
              <div className="text-xs text-slate-500">criticality weight ×{risk.asset_criticality_weight}</div>
              {risk.rationale && <p className="mt-1 text-xs text-slate-400">{risk.rationale}</p>}
            </div>
          ) : (
            <span className="text-slate-500">no score</span>
          )}
        </div>
        <div>
          <div className="mb-1 text-xs uppercase text-slate-500">Compliance</div>
          {compliance.length === 0 ? (
            <span className="text-slate-500">no mappings</span>
          ) : (
            <ul className="space-y-1">
              {compliance.map((c, i) => (
                <li key={i} className="text-slate-300">
                  <span className="font-mono text-indigo-300">{c.framework}</span> {c.control_id}
                  {c.control_description && <span className="text-slate-500"> — {c.control_description}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs uppercase text-slate-500">Remediation</span>
          <Button variant="ghost" onClick={genRemediation} disabled={genBusy}>
            {genBusy ? "Generating…" : remediation ? "Regenerate" : "Generate"}
          </Button>
        </div>
        {remediation ? (
          <div className="rounded-md bg-slate-900/60 p-3">
            {remediation.summary && <p className="mb-2 text-slate-300">{remediation.summary}</p>}
            {remediation.steps?.length > 0 && (
              <ol className="ml-4 list-decimal space-y-1 text-slate-300">
                {remediation.steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            )}
            {remediation.references?.length > 0 && (
              <div className="mt-2 space-x-3 text-xs">
                {remediation.references.map((r, i) => (
                  <a key={i} href={r.url} target="_blank" rel="noreferrer" className="text-indigo-400 hover:underline">
                    {r.title}
                  </a>
                ))}
              </div>
            )}
            <div className="mt-2 text-xs text-slate-500">generated by {remediation.generated_by}</div>
          </div>
        ) : (
          <span className="text-slate-500">none yet</span>
        )}
      </div>

      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">Triage</div>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label>Set status</Label>
            <Select value={newStatus} onChange={(e) => setNewStatus(e.target.value)}>
              {STATUS_CHOICES.map((s) => (
                <option key={s} value={s}>
                  {s.replace("_", " ")}
                </option>
              ))}
            </Select>
          </div>
          <div className="min-w-[14rem] flex-1">
            <Label>Justification</Label>
            <input
              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 outline-none focus:border-indigo-600"
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="why"
            />
          </div>
          <Button onClick={applyStatus} disabled={busy}>
            Apply
          </Button>
        </div>
        <ErrorText>{err}</ErrorText>
      </div>
    </div>
  );
}
