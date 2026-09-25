"use client";

// Client Risk Assessments: the list, the create/issue flow, and the detail view showing the
// FROZEN posture, top risks, remediation progress and the trend against the previous issued
// snapshot.
//
// THE THING THIS UI MUST NOT DO: present a live figure as if it were part of an issued
// assessment. An issued assessment renders ONLY from `summary` (the frozen snapshot) and its
// frozen findings; the live "current posture" panel is shown separately, on the list, and is
// explicitly labelled as such.

import { useCallback, useEffect, useState } from "react";

import {
  assessmentApi,
  type AssessmentComparison,
  type AssessmentFinding,
  type AssessmentSummary,
  type RiskAssessment,
} from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Badge, Button, Card, Empty, ErrorText, Input, Label, Spinner } from "@/components/ui";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

function isoToDate(value: string | null | undefined): string {
  return value ? value.slice(0, 10) : "";
}

/** UTC midnight, explicitly -- `new Date(v).toISOString()` would reinterpret the picker value
 *  in the browser's local zone and shift the period boundary by a day. */
function dateToIso(value: string): string {
  return `${value}T00:00:00Z`;
}

export function AssessmentsTab({ projectId }: { projectId: string }) {
  const { t } = useTranslation();
  const [assessments, setAssessments] = useState<RiskAssessment[] | null>(null);
  const [preview, setPreview] = useState<AssessmentSummary | null>(null);
  const [error, setError] = useState("");
  const [openId, setOpenId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setAssessments(await assessmentApi.list(projectId));
      setError("");
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId]);

  useEffect(() => {
    load();
    // Live posture, read-only. Failure is non-fatal: the list is the primary content.
    assessmentApi.preview(projectId).then(setPreview).catch(() => {});
  }, [projectId, load]);

  return (
    <div className="space-y-6">
      <CreateAssessment projectId={projectId} onCreated={load} />

      {preview && (
        <Card>
          <div className="mb-1 text-xs uppercase tracking-wide text-slate-500">
            {t("assessment.preview")}
          </div>
          <p className="mb-3 text-xs text-slate-500">{t("assessment.previewHint")}</p>
          <ScorePanel score={preview.security_score} band={preview.score_band} />
          <SeverityRow counts={preview.active_severity_counts} />
        </Card>
      )}

      <ErrorText>{error}</ErrorText>

      {assessments === null ? (
        <Spinner />
      ) : assessments.length === 0 ? (
        <Empty>{t("assessment.empty")}</Empty>
      ) : (
        <div className="space-y-3">
          {assessments.map((a) => (
            <Card key={a.id}>
              <button
                className="flex w-full items-center justify-between gap-3 text-left"
                onClick={() => setOpenId(openId === a.id ? null : a.id)}
              >
                <div>
                  <div className="font-medium text-slate-100">{a.title}</div>
                  <div className="text-xs text-slate-500">
                    {isoToDate(a.period_start)} → {isoToDate(a.period_end)}
                    {a.issued_at && ` · ${t("assessment.issuedOn")} ${isoToDate(a.issued_at)}`}
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  {/* NULL score on a draft is shown as an em dash, never as 0 -- 0 would be a
                      real (terrible) posture, which a draft has not measured. */}
                  <span className="text-lg font-semibold text-slate-100">
                    {a.security_score ?? "—"}
                  </span>
                  <Badge kind="status" value={a.status} />
                </div>
              </button>
              {openId === a.id && (
                <AssessmentDetail projectId={projectId} assessment={a} onChange={load} />
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function CreateAssessment({ projectId, onCreated }: { projectId: string; onCreated: () => void }) {
  const { t } = useTranslation();
  const [title, setTitle] = useState("");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function create() {
    setBusy(true);
    setErr("");
    try {
      await assessmentApi.create(projectId, title, dateToIso(start), dateToIso(end));
      setTitle("");
      setStart("");
      setEnd("");
      onCreated();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-[12rem] flex-1">
          <Label>{t("assessment.name")}</Label>
          <Input value={title} onChange={(e) => setTitle(e.target.value)} />
        </div>
        <div>
          <Label>{t("assessment.periodStart")}</Label>
          <Input type="date" value={start} onChange={(e) => setStart(e.target.value)} />
        </div>
        <div>
          <Label>{t("assessment.periodEnd")}</Label>
          <Input type="date" value={end} onChange={(e) => setEnd(e.target.value)} />
        </div>
        <Button onClick={create} disabled={busy || !title.trim() || !start || !end}>
          {busy ? t("assessment.creating") : t("assessment.create")}
        </Button>
      </div>
      <ErrorText>{err}</ErrorText>
    </Card>
  );
}

function ScorePanel({ score, band }: { score: number | null; band: string | null }) {
  const { t } = useTranslation();
  return (
    <div className="mb-3 flex items-baseline gap-3">
      <span className="text-3xl font-semibold text-slate-100">{score ?? "—"}</span>
      <span className="text-slate-500">/ 100</span>
      {band && <span className="text-sm text-accent-cyan">{band}</span>}
      <span className="ms-auto text-xs uppercase text-slate-500">{t("assessment.securityScore")}</span>
    </div>
  );
}

function SeverityRow({ counts }: { counts: Record<string, number> | undefined }) {
  const { t } = useTranslation();
  if (!counts) return null;
  return (
    <div>
      <div className="mb-1 text-xs uppercase text-slate-500">{t("assessment.severityPosture")}</div>
      <div className="flex flex-wrap gap-2">
        {SEVERITY_ORDER.map((sev) => (
          <span key={sev} className="flex items-center gap-1.5">
            <Badge kind="severity" value={sev} />
            <span className="text-sm text-slate-300">{counts[sev] ?? 0}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function AssessmentDetail({
  projectId,
  assessment,
  onChange,
}: {
  projectId: string;
  assessment: RiskAssessment;
  onChange: () => void;
}) {
  const { t } = useTranslation();
  const [findings, setFindings] = useState<AssessmentFinding[]>([]);
  const [comparison, setComparison] = useState<AssessmentComparison | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const issued = assessment.status === "issued";
  const summary = assessment.summary || {};

  useEffect(() => {
    if (!issued) return;
    assessmentApi.findings(projectId, assessment.id).then(setFindings).catch(() => {});
    assessmentApi.comparison(projectId, assessment.id).then(setComparison).catch(() => {});
  }, [projectId, assessment.id, issued]);

  async function issue() {
    setBusy(true);
    setErr("");
    try {
      await assessmentApi.issue(projectId, assessment.id);
      onChange();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  if (!issued) {
    return (
      <div className="mt-4 space-y-3 border-t border-slate-800 pt-4 text-sm">
        <p className="text-xs text-slate-500">{t("assessment.issueHint")}</p>
        <Button onClick={issue} disabled={busy}>
          {busy ? t("assessment.issuing") : t("assessment.issue")}
        </Button>
        <ErrorText>{err}</ErrorText>
      </div>
    );
  }

  const progress = summary.remediation_progress;

  return (
    <div className="mt-4 space-y-5 border-t border-slate-800 pt-4 text-sm">
      <p className="text-xs text-slate-500">{t("assessment.frozenNote")}</p>

      <div>
        <ScorePanel score={assessment.security_score} band={assessment.score_band} />
        <SeverityRow counts={summary.active_severity_counts} />
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Metric label={t("assessment.unresolvedIssues")} value={summary.unresolved_issue_count} />
          <Metric label={t("assessment.affectedAssets")} value={summary.affected_assets?.length} />
          <Metric label={t("assessment.affectedEndpoints")} value={summary.affected_endpoint_count} />
        </div>
      </div>

      {/* --- trend --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("assessment.trend")}</div>
        {!comparison?.has_previous ? (
          <span className="text-slate-500">{t("assessment.noPrevious")}</span>
        ) : (
          <p className="text-slate-300">
            {t("assessment.comparedTo")}: {comparison.previous_security_score} →{" "}
            {assessment.security_score}{" "}
            <span
              className={
                comparison.direction === "improved"
                  ? "text-emerald-300"
                  : comparison.direction === "declined"
                    ? "text-rose-300"
                    : "text-slate-400"
              }
            >
              (
              {comparison.direction === "improved"
                ? t("assessment.improved")
                : comparison.direction === "declined"
                  ? t("assessment.declined")
                  : t("assessment.unchanged")}
              {typeof comparison.security_score_delta === "number" &&
                comparison.security_score_delta !== 0 &&
                `, ${Math.abs(comparison.security_score_delta)} ${t("assessment.points")}`}
              )
            </span>
          </p>
        )}
      </div>

      {/* --- top risks --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("assessment.topRisks")}</div>
        {!summary.top_risks?.length ? (
          <span className="text-slate-500">{t("assessment.noTopRisks")}</span>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <tbody>
                {summary.top_risks.map((risk, i) => (
                  <tr key={i} className="border-b border-slate-800/60 last:border-0">
                    <td className="py-2 pe-3">
                      <Badge kind="severity" value={risk.severity} />
                    </td>
                    <td className="py-2 pe-3 text-slate-200">{risk.title}</td>
                    {/* "N/A", never 0.0 -- an unscored risk and a risk scored zero are
                        different facts, exactly as in the PDF. */}
                    <td className="py-2 pe-3 text-slate-400" dir="ltr">
                      {risk.max_risk ?? "N/A"}
                    </td>
                    <td className="py-2 text-xs text-slate-500">
                      {risk.endpoint_count} {t("assessment.endpointCount")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* --- remediation progress --- */}
      {progress && (
        <div className="border-t border-slate-800 pt-4">
          <div className="mb-2 text-xs uppercase text-slate-500">
            {t("assessment.remediationProgress")}
          </div>
          <div className="mb-2 h-2 w-full overflow-hidden rounded-full bg-white/5">
            <div
              className="h-full rounded-full bg-accent-cyan"
              style={{ width: `${progress.completion_percent}%` }}
            />
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label={t("remediation.progressTotal")} value={progress.total} />
            <Metric label={t("remediation.progressOpen")} value={progress.open} />
            <Metric label={t("remediation.progressResolved")} value={progress.resolved} />
            <Metric label={t("remediation.overdue")} value={progress.overdue} />
          </div>
        </div>
      )}

      {/* --- recommendations --- */}
      {assessment.narrative && (
        <div className="border-t border-slate-800 pt-4">
          <div className="mb-2 text-xs uppercase text-slate-500">
            {t("assessment.recommendations")}
          </div>
          <div className="space-y-1 whitespace-pre-line text-slate-300">{assessment.narrative}</div>
        </div>
      )}

      {/* --- frozen findings --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("assessment.findings")}</div>
        {findings.length === 0 ? (
          <span className="text-slate-500">{t("assessment.noFindings")}</span>
        ) : (
          <ul className="space-y-2">
            {findings.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-2">
                <Badge kind="severity" value={f.frozen_severity} />
                <span className="text-slate-200">{f.frozen_title}</span>
                {f.frozen_cvss_score != null && (
                  <span className="text-xs text-slate-500" dir="ltr">
                    CVSS {f.frozen_cvss_score}
                  </span>
                )}
                {f.frozen_remediation_status && (
                  <Badge kind="status" value={f.frozen_remediation_status} />
                )}
                {f.risk_accepted && (
                  <span className="rounded border border-slate-600 px-1.5 py-0.5 text-[10px] uppercase text-slate-400">
                    {t("assessment.riskAccepted")}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      <ErrorText>{err}</ErrorText>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div>
      <div className="text-xl font-semibold text-slate-100">{value ?? 0}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}
