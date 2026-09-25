"use client";

// Project-level remediation workspace: the list, its filters, and the per-item detail with
// timeline / evidence / verification / risk treatment.
//
// Reuses the existing project chrome, the shared ui.tsx primitives, the existing Badge status
// styling and the existing api client -- no new frontend architecture.
//
// TWO THINGS THIS UI IS CAREFUL ABOUT, because the backend enforces them and a UI that implied
// otherwise would be misleading:
//   1. `verified` and `risk_accepted` are NOT offered in the status dropdown. They are reached
//      only through the verification flow (a real retest) and the risk-acceptance form.
//   2. Every mutation sends the item's `version`. A 409 means someone else changed it first,
//      and the UI says so and reloads rather than retrying blindly.

import { useCallback, useEffect, useState } from "react";

import {
  ApiError,
  REMEDIATION_PRIORITIES,
  REMEDIATION_TRANSITION_TARGETS,
  remediationApi,
  memberApi,
  type Member,
  type RemediationEvent,
  type RemediationEvidence,
  type RemediationItem,
  type RemediationProgress,
  type RiskAcceptance,
  type VerificationRequest,
} from "@/lib/api";
import { useTranslation } from "@/lib/i18n";
import { Badge, Button, Card, Empty, ErrorText, Input, Label, Select, Spinner } from "@/components/ui";

const STATUS_FILTERS = [
  "", "proposed", "accepted", "in_progress", "awaiting_verification",
  "verified", "closed", "risk_accepted", "rejected", "reopened",
];

/** ISO 8601 (what the API expects) from an <input type="date"> value, at UTC midnight.
 *  `T00:00:00Z` explicitly rather than `new Date(v).toISOString()`, which would interpret the
 *  value in the browser's LOCAL zone and shift the due date by a day either side of UTC. */
function dateToIso(value: string): string | undefined {
  return value ? `${value}T00:00:00Z` : undefined;
}

/** ISO -> the `yyyy-mm-dd` an <input type="date"> requires. */
function isoToDate(value: string | null): string {
  return value ? value.slice(0, 10) : "";
}

export function RemediationTab({ projectId }: { projectId: string }) {
  const { t } = useTranslation();
  const [items, setItems] = useState<RemediationItem[] | null>(null);
  const [progress, setProgress] = useState<RemediationProgress | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [error, setError] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [list, prog] = await Promise.all([
        remediationApi.list(projectId, {
          status: status || undefined,
          priority: priority || undefined,
          overdue: overdueOnly || undefined,
        }),
        remediationApi.progress(projectId),
      ]);
      setItems(list);
      setProgress(prog);
      setError("");
    } catch (e: any) {
      setError(e.message);
    }
  }, [projectId, status, priority, overdueOnly]);

  useEffect(() => {
    load();
  }, [load]);

  // Members drive the assignee picker. Fetched once: an assignee must be a workspace member,
  // and the server refuses anything else, so the picker should only ever offer valid choices.
  // Failure is non-fatal -- the rest of the tab still works, the picker is just empty.
  useEffect(() => {
    memberApi.list().then(setMembers).catch(() => {});
  }, []);

  async function sync() {
    setSyncing(true);
    setError("");
    try {
      await remediationApi.sync(projectId);
      await load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setSyncing(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label htmlFor="rem-filter-status">{t("remediation.status")}</Label>
            <Select id="rem-filter-status" value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS_FILTERS.map((s) => (
                <option key={s} value={s}>
                  {s ? s.replace(/_/g, " ") : t("remediation.all")}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="rem-filter-priority">{t("remediation.priority")}</Label>
            <Select id="rem-filter-priority" value={priority} onChange={(e) => setPriority(e.target.value)}>
              <option value="">{t("remediation.all")}</option>
              {REMEDIATION_PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          </div>
          <label className="flex items-center gap-2 pb-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={overdueOnly}
              onChange={(e) => setOverdueOnly(e.target.checked)}
              className="h-4 w-4 rounded border-cyber-border bg-white/5"
            />
            {t("remediation.overdueOnly")}
          </label>
          <div className="ms-auto">
            <Button onClick={sync} disabled={syncing}>
              {syncing ? t("remediation.syncing") : t("remediation.sync")}
            </Button>
            <p className="mt-1 max-w-xs text-xs text-slate-500">{t("remediation.syncHint")}</p>
          </div>
        </div>
      </Card>

      {progress && <ProgressPanel progress={progress} />}

      <ErrorText>{error}</ErrorText>

      {items === null ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Empty>{t("remediation.empty")}</Empty>
      ) : (
        <div className="space-y-3">
          {items.map((item) => (
            <Card key={item.id}>
              <button
                className="flex w-full items-center justify-between gap-3 text-left"
                onClick={() => setOpenId(openId === item.id ? null : item.id)}
              >
                <div className="flex items-center gap-3">
                  <Badge kind="severity" value={item.priority} />
                  <div>
                    <div className="font-medium text-slate-100">{item.title}</div>
                    <div className="text-xs text-slate-500">
                      <span dir="ltr">{item.issue_key}</span>
                      {item.due_date && ` · ${t("remediation.dueDate")}: ${isoToDate(item.due_date)}`}
                      {isOverdue(item) && (
                        <span className="ms-2 rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 text-[10px] font-medium uppercase text-rose-300">
                          {t("remediation.overdue")}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <Badge kind="status" value={item.status} />
              </button>
              {openId === item.id && (
                <RemediationDetail
                  projectId={projectId}
                  item={item}
                  members={members}
                  onChange={load}
                />
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

/** Mirrors the server's rule exactly: a due date in the past AND work still outstanding.
 *  Finished work past its due date is DONE, not overdue -- showing it as overdue would
 *  contradict the progress panel, whose counts come from the same rule server-side. */
function isOverdue(item: RemediationItem): boolean {
  const OUTSTANDING = ["proposed", "accepted", "in_progress", "awaiting_verification", "reopened"];
  if (!item.due_date || !OUTSTANDING.includes(item.status)) return false;
  return new Date(item.due_date).getTime() < Date.now();
}

function ProgressPanel({ progress }: { progress: RemediationProgress }) {
  const { t } = useTranslation();
  const cells: [string, number][] = [
    [t("remediation.progressTotal"), progress.total],
    [t("remediation.progressOpen"), progress.open],
    [t("remediation.progressResolved"), progress.resolved],
    [t("remediation.overdue"), progress.overdue],
  ];
  return (
    <Card>
      <div className="mb-3 flex items-baseline justify-between">
        <span className="text-xs uppercase tracking-wide text-slate-500">{t("remediation.progress")}</span>
        <span className="text-sm text-slate-300">
          {progress.completion_percent}% {t("remediation.progressComplete")}
        </span>
      </div>
      <div className="mb-3 h-2 w-full overflow-hidden rounded-full bg-white/5">
        <div
          className="h-full rounded-full bg-accent-cyan transition-all"
          style={{ width: `${progress.completion_percent}%` }}
        />
      </div>
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {cells.map(([label, value]) => (
          <div key={label}>
            <div className="text-xl font-semibold text-slate-100">{value}</div>
            <div className="text-xs text-slate-500">{label}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function RemediationDetail({
  projectId,
  item,
  members,
  onChange,
}: {
  projectId: string;
  item: RemediationItem;
  members: Member[];
  onChange: () => void;
}) {
  const { t } = useTranslation();
  const [events, setEvents] = useState<RemediationEvent[]>([]);
  const [evidence, setEvidence] = useState<RemediationEvidence[]>([]);
  const [verifications, setVerifications] = useState<VerificationRequest[]>([]);
  const [acceptances, setAcceptances] = useState<RiskAcceptance[]>([]);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const [assignee, setAssignee] = useState(item.assignee_user_id ?? "");
  const [dueDate, setDueDate] = useState(isoToDate(item.due_date));
  const [priority, setPriority] = useState(item.priority);
  const [notes, setNotes] = useState(item.notes ?? "");
  const [nextStatus, setNextStatus] = useState<string>("accepted");

  const loadDetail = useCallback(() => {
    remediationApi.events(projectId, item.id).then(setEvents).catch(() => {});
    remediationApi.evidence(projectId, item.id).then(setEvidence).catch(() => {});
    remediationApi.verifications(projectId, item.id).then(setVerifications).catch(() => {});
    // Risk acceptances need only `remediation:read`, but a role without it simply sees none --
    // a failure here must not blank the whole detail panel.
    remediationApi
      .riskAcceptances(projectId, item.vulnerability_id ?? undefined)
      .then(setAcceptances)
      .catch(() => {});
  }, [projectId, item.id, item.vulnerability_id]);

  useEffect(loadDetail, [loadDetail]);

  /** Every mutation funnels through here so the 409 (stale version) message is stated once,
   *  in the user's language, and always followed by a reload -- retrying with the same stale
   *  version would fail identically. */
  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setErr("");
    try {
      await action();
      loadDetail();
      onChange();
    } catch (e: any) {
      setErr(e instanceof ApiError && e.status === 409 ? t("remediation.conflict") : e.message);
      if (e instanceof ApiError && e.status === 409) onChange();
    } finally {
      setBusy(false);
    }
  }

  const save = () =>
    run(() =>
      remediationApi.update(projectId, item.id, {
        version: item.version,
        // Explicit clear flags rather than sending null: an omitted field means "unchanged"
        // server-side, so clearing needs its own signal.
        assignee_user_id: assignee || undefined,
        clear_assignee: !assignee && !!item.assignee_user_id,
        due_date: dateToIso(dueDate),
        clear_due_date: !dueDate && !!item.due_date,
        priority,
        notes,
      })
    );

  const transition = () =>
    run(() => remediationApi.transition(projectId, item.id, item.version, nextStatus));

  const requestVerification = () =>
    run(() => remediationApi.requestVerification(projectId, item.id, item.version));

  async function uploadEvidence(file: File) {
    const buffer = await file.arrayBuffer();
    // btoa needs a binary string; chunked to stay well under the argument limit for large files.
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    await run(() =>
      remediationApi.uploadEvidence(
        projectId, item.id, file.name, btoa(binary), file.type || "application/octet-stream"
      )
    );
  }

  return (
    <div className="mt-4 space-y-5 border-t border-slate-800 pt-4 text-sm">
      <ErrorText>{err}</ErrorText>

      {/* --- owner / due date / priority / notes --- */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <Label htmlFor="rem-assignee">{t("remediation.assignee")}</Label>
          <Select id="rem-assignee" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
            <option value="">{t("remediation.unassigned")}</option>
            {members.map((m) => (
              <option key={m.user_id} value={m.user_id}>
                {m.full_name || m.email}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="rem-due-date">{t("remediation.dueDate")}</Label>
          <Input id="rem-due-date" type="date" value={dueDate} onChange={(e) => setDueDate(e.target.value)} />
        </div>
        <div>
          <Label htmlFor="rem-priority">{t("remediation.priority")}</Label>
          <Select id="rem-priority" value={priority} onChange={(e) => setPriority(e.target.value as typeof priority)}>
            {REMEDIATION_PRIORITIES.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="rem-notes">{t("remediation.notes")}</Label>
          <Input
            id="rem-notes"
            value={notes}
            placeholder={t("remediation.notesPlaceholder")}
            onChange={(e) => setNotes(e.target.value)}
          />
          {item.notes_source && (
            <p className="mt-1 text-xs text-slate-500">
              {t("remediation.notesBy")}:{" "}
              {item.notes_source === "ai" ? t("remediation.sourceAi") : t("remediation.sourceHuman")}
            </p>
          )}
        </div>
      </div>
      <div className="flex items-center gap-3">
        <Button onClick={save} disabled={busy}>
          {t("remediation.save")}
        </Button>
        <span className="text-xs text-slate-500">
          {t("remediation.version")} {item.version}
        </span>
      </div>

      {/* --- status transition --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("remediation.transition")}</div>
        <div className="flex flex-wrap items-end gap-3">
          <Select value={nextStatus} onChange={(e) => setNextStatus(e.target.value)}>
            {/* `verified` and `risk_accepted` are absent BY DESIGN -- see the file header. */}
            {REMEDIATION_TRANSITION_TARGETS.map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, " ")}
              </option>
            ))}
          </Select>
          <Button onClick={transition} disabled={busy}>
            {t("remediation.apply")}
          </Button>
        </div>
      </div>

      {/* --- verification --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs uppercase text-slate-500">{t("remediation.verification")}</span>
          <Button variant="ghost" onClick={requestVerification} disabled={busy}>
            {t("remediation.requestVerification")}
          </Button>
        </div>
        <p className="mb-2 text-xs text-slate-500">{t("remediation.verificationHint")}</p>
        {verifications.length === 0 ? (
          <span className="text-slate-500">{t("remediation.noVerification")}</span>
        ) : (
          <ul className="space-y-2">
            {verifications.map((v) => (
              <li key={v.id} className="rounded-md bg-slate-900/60 p-3">
                <div className="flex items-center gap-2">
                  <Badge kind="status" value={v.status} />
                  {v.result && (
                    <span className="text-xs text-slate-300">
                      {t("remediation.verificationResult")}:{" "}
                      {v.result === "passed"
                        ? t("remediation.verificationPassed")
                        : t("remediation.verificationFailed")}
                    </span>
                  )}
                </div>
                {/* The reproducible basis for the verdict, shown rather than summarised, so a
                    reader can check it against the scan themselves. */}
                {typeof v.detail?.live_locations === "number" && (
                  <div className="mt-1 text-xs text-slate-500">
                    {v.detail.live_locations} {t("remediation.liveLocations")}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* --- evidence --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("remediation.evidence")}</div>
        <p className="mb-2 text-xs text-slate-500">{t("remediation.evidenceHint")}</p>
        <input
          type="file"
          disabled={busy}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) uploadEvidence(file);
            e.target.value = "";
          }}
          className="mb-2 block w-full text-xs text-slate-400 file:me-3 file:rounded-lg file:border file:border-cyber-border file:bg-white/5 file:px-3 file:py-1.5 file:text-slate-200"
        />
        {evidence.length === 0 ? (
          <span className="text-slate-500">{t("remediation.noEvidence")}</span>
        ) : (
          <ul className="space-y-1">
            {evidence.map((e) => (
              <li key={e.id} className="text-xs text-slate-400">
                <span dir="ltr">{e.storage_uri}</span>
                <span className="ms-2 text-slate-600">sha256:{e.checksum.slice(0, 12)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* --- risk treatment --- */}
      <RiskTreatment
        projectId={projectId}
        item={item}
        acceptances={acceptances}
        busy={busy}
        onRun={run}
      />

      {/* --- timeline --- */}
      <div className="border-t border-slate-800 pt-4">
        <div className="mb-2 text-xs uppercase text-slate-500">{t("remediation.timeline")}</div>
        <ol className="space-y-2">
          {events.map((e) => (
            <li key={e.id} className="flex gap-3 text-xs">
              <span className="whitespace-nowrap text-slate-500">
                {new Date(e.created_at).toLocaleString()}
              </span>
              <span className="text-slate-300">
                {e.event_type.replace(/_/g, " ")}
                {e.from_status && e.to_status && (
                  <span className="text-slate-500">
                    {" "}
                    ({e.from_status} → {e.to_status})
                  </span>
                )}
                {e.detail && <span className="text-slate-500"> — {e.detail}</span>}
              </span>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function RiskTreatment({
  projectId,
  item,
  acceptances,
  busy,
  onRun,
}: {
  projectId: string;
  item: RemediationItem;
  acceptances: RiskAcceptance[];
  busy: boolean;
  onRun: (action: () => Promise<unknown>) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [justification, setJustification] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [denied, setDenied] = useState(false);

  // The accept form is only meaningful when the item is tied to a vulnerability -- risk is
  // accepted for a FINDING, not for a work item in the abstract.
  const canAccept = !!item.vulnerability_id;

  async function accept() {
    if (!item.vulnerability_id) return;
    await onRun(async () => {
      try {
        return await remediationApi.acceptRisk(projectId, {
          vulnerability_id: item.vulnerability_id!,
          justification,
          expires_at: dateToIso(expiresAt)!,
          remediation_item_id: item.id,
          version: item.version,
        });
      } catch (e) {
        // 403 = this role does not hold `risk:accept` (member and client_viewer never do).
        // Remember it so the form stops inviting an action the user cannot take.
        if (e instanceof ApiError && e.status === 403) setDenied(true);
        throw e;
      }
    });
    setJustification("");
    setExpiresAt("");
  }

  return (
    <div className="border-t border-slate-800 pt-4">
      <div className="mb-2 text-xs uppercase text-slate-500">{t("remediation.riskTreatment")}</div>
      <p className="mb-2 text-xs text-slate-500">{t("remediation.riskHint")}</p>

      {acceptances.length === 0 ? (
        <span className="text-slate-500">{t("remediation.noAcceptances")}</span>
      ) : (
        <ul className="mb-3 space-y-2">
          {acceptances.map((a) => (
            <li key={a.id} className="rounded-md bg-slate-900/60 p-3">
              <div className="flex items-center gap-2">
                <Badge kind="status" value={a.status} />
                <span className="text-xs text-slate-500">
                  {t("remediation.expiresAt")} {isoToDate(a.expires_at)}
                </span>
              </div>
              <p className="mt-1 text-slate-300">{a.justification}</p>
              {a.status === "active" && (
                <Button
                  variant="ghost"
                  disabled={busy}
                  onClick={() =>
                    onRun(() =>
                      remediationApi.revokeRiskAcceptance(projectId, a.id, t("remediation.revoke"))
                    )
                  }
                >
                  {t("remediation.revoke")}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}

      {canAccept && !denied && (
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[14rem] flex-1">
            <Label htmlFor="rem-justification">{t("remediation.justification")}</Label>
            <Input id="rem-justification" value={justification} onChange={(e) => setJustification(e.target.value)} />
          </div>
          <div>
            <Label htmlFor="rem-expires-at">{t("remediation.expiresAt")}</Label>
            <Input id="rem-expires-at" type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          </div>
          <Button
            variant="secondary"
            onClick={accept}
            // Both are REQUIRED server-side: an acceptance with no reason, or one that never
            // lapses, is not an accepted risk. Disabling here states that up front.
            disabled={busy || !justification.trim() || !expiresAt}
          >
            {t("remediation.acceptRisk")}
          </Button>
        </div>
      )}
    </div>
  );
}
