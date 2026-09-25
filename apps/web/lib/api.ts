// Browser-side API client for MBS.SC. Handles bearer auth, one-shot refresh on
// 401, and workspace-scoped URLs.
//
// F-08 -- TOKEN STORAGE. Both tokens used to live in localStorage, where any XSS could read
// them; the refresh token in particular was a 7-day credential sitting in JS reach. Now:
//   * refresh token -> HttpOnly cookie set by the API. This file NEVER sees it, never stores
//     it and cannot read it; `credentials: "include"` is what carries it back on /auth/*.
//   * access token  -> MEMORY ONLY (the `accessToken` binding below). Not persisted, so a
//     reload deliberately drops it and the app re-obtains one from the refresh cookie.
//   * workspace id  -> still localStorage, but it is a UI HINT ONLY. The backend derives
//     authorization from the authenticated identity and returns 403 for another tenant's
//     workspace (verified live), so tampering with it grants nothing.
//
// API_BASE is now RELATIVE by default so the browser talks to the API SAME-ORIGIN through
// nginx (/api/v1/... -> api:8000). That is what makes SameSite=strict on the refresh cookie
// workable, and it is the CSRF control for the cookie-authenticated /auth routes.
const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "") + "/api/v1";

const WORKSPACE_KEY = "mbs_workspace";

// The access token lives here and nowhere else. Module scope = per-tab memory: cleared by a
// reload, never written to localStorage/sessionStorage, never readable from another origin.
let accessToken: string | null = null;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const tokens = {
  /** In-memory access token. There is deliberately no persistent read path. */
  get access() {
    return accessToken;
  },
  /** F-08: the refresh token is an HttpOnly cookie -- unreadable by design. Kept as an
   *  explicit null-returning accessor so any lingering caller fails loudly rather than
   *  silently reaching into storage. */
  get refresh(): null {
    return null;
  },
  /** `refresh` is accepted and ignored: the API sets it as a cookie. The parameter stays so
   *  existing call sites keep compiling while the token never reaches storage. */
  set(access: string, _refresh?: string) {
    accessToken = access;
  },
  clear() {
    accessToken = null;
    if (typeof window !== "undefined") localStorage.removeItem(WORKSPACE_KEY);
  },
};

export const workspace = {
  get id() {
    return typeof window === "undefined" ? null : localStorage.getItem(WORKSPACE_KEY);
  },
  set(id: string) {
    localStorage.setItem(WORKSPACE_KEY, id);
  },
};

async function parse(res: Response) {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function rawFetch(path: string, init: RequestInit, withAuth: boolean): Promise<Response> {
  const headers: Record<string, string> = { ...(init.headers as Record<string, string>) };
  if (init.body) headers["Content-Type"] = "application/json";
  if (withAuth && tokens.access) headers["Authorization"] = `Bearer ${tokens.access}`;
  // F-08: `credentials: "include"` is what carries the HttpOnly refresh cookie on /auth/*.
  // It is safe to send on every call: the cookie is Path-scoped to /api/v1/auth, so the
  // browser does not attach it to ordinary API requests.
  return fetch(API_BASE + path, { ...init, headers, credentials: "include" });
}

// F-08: a single in-flight refresh shared by all callers. Without this, N concurrent 401s
// would each rotate the refresh token; because rotation is one-use with reuse detection
// (F-04), the later rotations would look like a replay and revoke the whole family -- logging
// the user out on nothing more than a burst of parallel requests.
let refreshInFlight: Promise<boolean> | null = null;

// The in-flight promise above only de-dupes OVERLAPPING callers -- it is cleared in `finally`,
// the moment the request settles. React StrictMode (next.config.mjs: reactStrictMode, active in
// development) invokes effects twice, and the SECOND mount starts AFTER the first refresh has
// already settled, so the flag is null again and a second rotation fires. Measured against a
// model of this exact function: overlapping callers = 1 network refresh, but StrictMode's
// sequential pair = 2.
//
// Two rotations means the second request presents a cookie the first one just rotated away.
// Server-side that is indistinguishable from a stolen-token replay, so F-04 revokes the whole
// token family -- verified live: refresh C1 -> 200, replay C1 -> 401, and the legitimately
// rotated C2 -> 401. Session recovery then fails on every reload.
//
// Remembering the settled result for a very short window makes the second, redundant mount
// reuse the first outcome instead of rotating again. This does NOT weaken anything: the window
// is far shorter than any token lifetime so a genuine later refresh still rotates normally,
// the refresh token is never read or stored by JS (it stays the HttpOnly cookie), rotation and
// replay detection are untouched, and by removing ACCIDENTAL reuse it makes a real F-04 alert
// more meaningful, not less.
const REFRESH_COALESCE_MS = 500;
let lastRefresh: { at: number; ok: boolean } | null = null;

async function tryRefresh(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;
  // Only a SUCCESS is ever coalesced (see below): a failure must always be retried, never
  // cached, so a transient error can never be replayed back to callers as a fake success.
  if (lastRefresh && Date.now() - lastRefresh.at < REFRESH_COALESCE_MS) return lastRefresh.ok;
  refreshInFlight = (async () => {
    try {
      // No body: the refresh token travels as the HttpOnly cookie. This file never holds it.
      const res = await rawFetch("/auth/refresh", { method: "POST" }, false);
      if (!res.ok) return false;
      const data = await parse(res);
      tokens.set(data.access_token);   // access token -> memory; cookie rotated server-side
      // Record the ACTUAL outcome of THIS attempt. Deliberately not a `tokens.access !== null`
      // probe: after an earlier successful auth that would report a stale success and cache a
      // failed refresh as `ok: true`.
      lastRefresh = { at: Date.now(), ok: true };
      return true;
    } catch {
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

export async function api<T = any>(
  path: string,
  opts: { method?: string; body?: unknown; auth?: boolean; raw?: boolean } = {}
): Promise<T> {
  const withAuth = opts.auth !== false;
  const init: RequestInit = {
    method: opts.method || "GET",
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  };

  let res = await rawFetch(path, init, withAuth);
  if (res.status === 401 && withAuth && (await tryRefresh())) {
    res = await rawFetch(path, init, withAuth);
  }
  if (opts.raw) return res as unknown as T;
  const data = await parse(res);
  if (!res.ok) {
    const detail = data && typeof data === "object" && "detail" in data ? (data as any).detail : data;
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data as T;
}

// workspace-scoped path helper
function ws(path: string): string {
  const id = workspace.id;
  if (!id) throw new ApiError(400, "No workspace selected");
  return `/workspaces/${id}${path}`;
}

// ---- Auth ----
export const authApi = {
  register: (email: string, password: string, full_name: string) =>
    api<{ access_token: string; refresh_token: string }>("/auth/register", {
      method: "POST",
      auth: false,
      body: { email, password, full_name },
    }),
  login: (email: string, password: string) =>
    api<{ access_token: string; refresh_token: string }>("/auth/login", {
      method: "POST",
      auth: false,
      body: { email, password },
    }),
  // F-08: no token in the body -- the API reads the HttpOnly cookie and clears it.
  logout: () => api("/auth/logout", { method: "POST" }),
  me: () => api<User>("/users/me"),
};

// ---- Profile ----
export const profileApi = {
  update: (full_name: string) => api<User>("/users/me", { method: "PATCH", body: { full_name } }),
  changePassword: (current_password: string, new_password: string) =>
    api<Response>("/users/me/change-password", {
      method: "POST",
      body: { current_password, new_password },
      raw: true,
    }),
};

// ---- Team / members ----
export const memberApi = {
  list: () => api<Member[]>(ws("/members")),
  roles: () => api<Role[]>("/roles"),
  invite: (email: string, role_name: string) =>
    api<Member>(ws("/members/invite"), { method: "POST", body: { email, role_name } }),
  updateRole: (userId: string, role_name: string) =>
    api<Member>(ws(`/members/${userId}/role`), { method: "PATCH", body: { role_name } }),
  remove: (userId: string) => api<Response>(ws(`/members/${userId}`), { method: "DELETE", raw: true }),
};

// ---- Workspaces ----
export const workspaceApi = {
  list: () => api<Workspace[]>("/workspaces"),
  create: (name: string) => api<Workspace>("/workspaces", { method: "POST", body: { name } }),
};

// ---- Dashboard ----
export const dashboardApi = {
  summary: () => api<DashboardSummary>(ws("/dashboard/summary")),
  recommendations: () => api<Recommendation[]>(ws("/dashboard/recommendations")),
};

// ---- Audit log ----
export const auditApi = {
  list: () => api<AuditEvent[]>(ws("/audit")),
};

// ---- API keys ----
export const apiKeyApi = {
  list: () => api<ApiKey[]>(ws("/api-keys")),
  create: (name: string) => api<ApiKeyCreated>(ws("/api-keys"), { method: "POST", body: { name } }),
  revoke: (id: string) => api<Response>(ws(`/api-keys/${id}`), { method: "DELETE", raw: true }),
};

// ---- Notifications ----
export const notificationApi = {
  list: (unread = false) => api<AppNotification[]>(ws(`/notifications${unread ? "?unread=true" : ""}`)),
  unreadCount: () => api<{ count: number }>(ws("/notifications/unread-count")),
  markRead: (id: string) => api<Response>(ws(`/notifications/${id}/read`), { method: "POST", raw: true }),
  markAllRead: () => api<Response>(ws("/notifications/read-all"), { method: "POST", raw: true }),
};

// ---- Billing / plans ----
export const billingApi = {
  usage: () => api<Usage>(ws("/billing/usage")),
  setPlan: (tier: string) => api<Usage>(ws("/billing/plan"), { method: "PATCH", body: { tier } }),
  plans: () => api<PlanCatalogItem[]>("/plans", { auth: false }),
};

// ---- Projects / targets / scope ----
export const projectApi = {
  list: () => api<Project[]>(ws("/projects")),
  create: (name: string, description?: string) =>
    api<Project>(ws("/projects"), { method: "POST", body: { name, description } }),
  get: (id: string) => api<Project>(ws(`/projects/${id}`)),
  targets: (pid: string) => api<Target[]>(ws(`/projects/${pid}/targets`)),
  addTarget: (pid: string, type: string, value: string, criticality: string) =>
    api<Target>(ws(`/projects/${pid}/targets`), { method: "POST", body: { type, value, criticality } }),
  setCriticality: (pid: string, tid: string, criticality: string) =>
    api<Target>(ws(`/projects/${pid}/targets/${tid}`), { method: "PATCH", body: { criticality } }),
  getScope: (pid: string, tid: string) =>
    api<AuthorizationScope>(ws(`/projects/${pid}/targets/${tid}/authorization-scope`)),
  submitScope: (pid: string, tid: string, proof_type: string, proof_reference: string) =>
    api<AuthorizationScope>(ws(`/projects/${pid}/targets/${tid}/authorization-scope`), {
      method: "POST",
      body: { proof_type, proof_reference },
    }),
  verifyScope: (pid: string, tid: string, active_testing_allowed: boolean) =>
    api<AuthorizationScope>(ws(`/projects/${pid}/targets/${tid}/authorization-scope/verify`), {
      method: "POST",
      body: { active_testing_allowed },
    }),
};

// ---- Scans ----
export const scanApi = {
  // The registered scanner pipeline, in execution order, straight from the backend's
  // TOOL_REGISTRY. The scan form, the schedule form and the progress widget all build
  // their tool lists from this rather than each carrying its own hardcoded copy --
  // those copies had drifted (amass/dnsx/whatweb/ffuf were registered and runnable but
  // absent from all of them, so they could never be selected and their tool runs were
  // filtered out of the progress view). Global, not workspace-scoped.
  pipeline: () => api<PipelineTool[]>("/scan-capabilities/pipeline"),
  list: (pid: string) => api<Scan[]>(ws(`/projects/${pid}/scans`)),
  create: (pid: string, target_id: string, scan_type: string, requested_modules: string[], use_ai_planner: boolean) =>
    api<Scan>(ws(`/projects/${pid}/scans`), {
      method: "POST",
      body: { target_id, scan_type, requested_modules, use_ai_planner },
    }),
  get: (pid: string, sid: string) => api<Scan>(ws(`/projects/${pid}/scans/${sid}`)),
  toolRuns: (pid: string, sid: string) => api<ToolRun[]>(ws(`/projects/${pid}/scans/${sid}/tool-runs`)),
  // Hard cancel (modules/scans/service.py): revokes the Celery task with terminate=True (SIGTERM),
  // killing the in-flight tool immediately -- not a wait-for-current-tool-to-finish cooperative stop.
  // The scan row flips to "cancelled" atomically; the killed tool's ToolRun row can be left at
  // "running" since it never gets to write its own final status.
  cancel: (pid: string, sid: string) => api<Scan>(ws(`/projects/${pid}/scans/${sid}/cancel`), { method: "POST" }),
};

// ---- Scheduled scans ----
export const scheduleApi = {
  list: (pid: string) => api<ScanSchedule[]>(ws(`/projects/${pid}/schedules`)),
  create: (
    pid: string,
    target_id: string,
    scan_type: string,
    requested_modules: string[],
    interval_minutes: number,
    use_ai_planner: boolean
  ) =>
    api<ScanSchedule>(ws(`/projects/${pid}/schedules`), {
      method: "POST",
      body: { target_id, scan_type, requested_modules, interval_minutes, use_ai_planner },
    }),
  update: (pid: string, sid: string, patch: { enabled?: boolean; interval_minutes?: number }) =>
    api<ScanSchedule>(ws(`/projects/${pid}/schedules/${sid}`), { method: "PATCH", body: patch }),
  remove: (pid: string, sid: string) =>
    api<Response>(ws(`/projects/${pid}/schedules/${sid}`), { method: "DELETE", raw: true }),
};

// ---- Vulnerabilities ----
export const vulnApi = {
  list: (pid: string, severity?: string, status?: string) => {
    const q = new URLSearchParams();
    if (severity) q.set("severity", severity);
    if (status) q.set("status", status);
    const qs = q.toString();
    return api<Vulnerability[]>(ws(`/projects/${pid}/vulnerabilities${qs ? "?" + qs : ""}`));
  },
  get: (pid: string, vid: string) => api<Vulnerability>(ws(`/projects/${pid}/vulnerabilities/${vid}`)),
  setStatus: (pid: string, vid: string, status: string, justification: string) =>
    api<Vulnerability>(ws(`/projects/${pid}/vulnerabilities/${vid}/status`), {
      method: "PATCH",
      body: { status, justification },
    }),
  risk: (pid: string, vid: string) => api<RiskScore>(ws(`/projects/${pid}/vulnerabilities/${vid}/risk`)),
  compliance: (pid: string, vid: string) =>
    api<ComplianceMapping[]>(ws(`/projects/${pid}/vulnerabilities/${vid}/compliance-mappings`)),
  getRemediation: (pid: string, vid: string) =>
    api<Remediation>(ws(`/projects/${pid}/vulnerabilities/${vid}/remediation`)),
  generateRemediation: (pid: string, vid: string) =>
    api<Remediation>(ws(`/projects/${pid}/vulnerabilities/${vid}/remediation`), { method: "POST" }),
};

// ---- AI status ----
export const aiApi = {
  status: () => api<AIStatus>("/ai/status"),
};

// ---- AI Security Assistant ----
export const assistantApi = {
  ask: (question: string, opts: { projectId?: string; vulnerabilityId?: string } = {}) =>
    api<AssistantAnswer>(ws("/assistant/ask"), {
      method: "POST",
      body: { question, project_id: opts.projectId, vulnerability_id: opts.vulnerabilityId },
    }),
};

// ---- Assets (discovered recon inventory: subdomains, live hosts, ports, services, URLs) ----
export const assetApi = {
  list: (pid: string) => api<Asset[]>(ws(`/projects/${pid}/assets?limit=200`)),
};

// ---- Reports ----
export const reportApi = {
  list: (pid: string) => api<Report[]>(ws(`/projects/${pid}/reports`)),
  create: (pid: string, type: string) => api<Report>(ws(`/projects/${pid}/reports`), { method: "POST", body: { type } }),
  downloadUrl: (pid: string, rid: string) => `${API_BASE}${ws(`/projects/${pid}/reports/${rid}/download`)}`,
  async download(pid: string, rid: string): Promise<Blob> {
    const res = await api<Response>(ws(`/projects/${pid}/reports/${rid}/download`), { raw: true });
    if (!res.ok) throw new ApiError(res.status, "Download failed");
    return res.blob();
  },
};

// ---- Remediation workflow ----
// Every mutating call carries the item's `version` -- the server compares-and-sets on it and
// returns 409 if someone else changed the item first, so a stale tab cannot silently clobber.
export const remediationApi = {
  list: (pid: string, filters: { status?: string; priority?: string; assignee?: string; overdue?: boolean } = {}) => {
    const q = new URLSearchParams();
    if (filters.status) q.set("status", filters.status);
    if (filters.priority) q.set("priority", filters.priority);
    if (filters.assignee) q.set("assignee_user_id", filters.assignee);
    if (filters.overdue) q.set("overdue", "true");
    const qs = q.toString();
    return api<RemediationItem[]>(ws(`/projects/${pid}/remediation${qs ? "?" + qs : ""}`));
  },
  get: (pid: string, id: string) => api<RemediationItem>(ws(`/projects/${pid}/remediation/${id}`)),
  sync: (pid: string) =>
    api<RemediationItem[]>(ws(`/projects/${pid}/remediation/sync`), { method: "POST" }),
  progress: (pid: string) => api<RemediationProgress>(ws(`/projects/${pid}/remediation/progress`)),
  update: (pid: string, id: string, patch: RemediationItemPatch) =>
    api<RemediationItem>(ws(`/projects/${pid}/remediation/${id}`), { method: "PATCH", body: patch }),
  transition: (pid: string, id: string, version: number, to_status: string, detail?: string) =>
    api<RemediationItem>(ws(`/projects/${pid}/remediation/${id}/transition`), {
      method: "POST",
      body: { version, to_status, detail },
    }),
  events: (pid: string, id: string) =>
    api<RemediationEvent[]>(ws(`/projects/${pid}/remediation/${id}/events`)),
  evidence: (pid: string, id: string) =>
    api<RemediationEvidence[]>(ws(`/projects/${pid}/remediation/${id}/evidence`)),
  // JSON + base64 rather than multipart: the API is JSON throughout, and multipart would mean
  // a new server dependency for one endpoint.
  uploadEvidence: (pid: string, id: string, filename: string, content_base64: string, content_type: string) =>
    api<RemediationEvidence>(ws(`/projects/${pid}/remediation/${id}/evidence`), {
      method: "POST",
      body: { filename, content_base64, content_type },
    }),
  verifications: (pid: string, id: string) =>
    api<VerificationRequest[]>(ws(`/projects/${pid}/remediation/${id}/verification`)),
  requestVerification: (pid: string, id: string, version: number, scan_id?: string) =>
    api<VerificationRequest>(ws(`/projects/${pid}/remediation/${id}/verification`), {
      method: "POST",
      body: { version, scan_id },
    }),
  // No body: there is deliberately no field through which a client could assert the outcome.
  // The server derives it from what the retest scan actually observed.
  completeVerification: (pid: string, requestId: string) =>
    api<VerificationRequest>(ws(`/projects/${pid}/remediation/verification/${requestId}/complete`), {
      method: "POST",
    }),
  riskAcceptances: (pid: string, vulnerabilityId?: string) => {
    const q = vulnerabilityId ? `?vulnerability_id=${vulnerabilityId}` : "";
    return api<RiskAcceptance[]>(ws(`/projects/${pid}/remediation/risk-acceptances${q}`));
  },
  acceptRisk: (pid: string, body: RiskAcceptanceCreate) =>
    api<RiskAcceptance>(ws(`/projects/${pid}/remediation/risk-acceptances`), { method: "POST", body }),
  revokeRiskAcceptance: (pid: string, id: string, reason: string) =>
    api<RiskAcceptance>(ws(`/projects/${pid}/remediation/risk-acceptances/${id}/revoke`), {
      method: "POST",
      body: { reason },
    }),
};

// ---- Client Risk Assessments ----
export const assessmentApi = {
  list: (pid: string) => api<RiskAssessment[]>(ws(`/projects/${pid}/risk-assessments`)),
  get: (pid: string, id: string) => api<RiskAssessment>(ws(`/projects/${pid}/risk-assessments/${id}`)),
  // Read-only live snapshot; creates and freezes nothing, so it is safe to call from the list view.
  preview: (pid: string) => api<AssessmentSummary>(ws(`/projects/${pid}/risk-assessments/preview`)),
  create: (pid: string, title: string, period_start: string, period_end: string) =>
    api<RiskAssessment>(ws(`/projects/${pid}/risk-assessments`), {
      method: "POST",
      body: { title, period_start, period_end },
    }),
  // IRREVERSIBLE: freezes the figures permanently.
  issue: (pid: string, id: string) =>
    api<RiskAssessment>(ws(`/projects/${pid}/risk-assessments/${id}/issue`), { method: "POST" }),
  findings: (pid: string, id: string) =>
    api<AssessmentFinding[]>(ws(`/projects/${pid}/risk-assessments/${id}/findings`)),
  comparison: (pid: string, id: string) =>
    api<AssessmentComparison>(ws(`/projects/${pid}/risk-assessments/${id}/comparison`)),
};

// ---- Types ----
export interface User { id: string; email: string; full_name: string; }
export interface Member {
  id: string; user_id: string; email: string; full_name: string; role_name: string;
  invited_at: string; joined_at: string | null;
}
export interface Role { id: string; workspace_id: string | null; name: string; description: string | null; }
export interface Workspace { id: string; name: string; plan_tier: string; }
export interface Project { id: string; name: string; description: string | null; status: string; created_at: string; }
export interface Target { id: string; type: string; value: string; criticality: string; created_at: string; }
export interface AuthorizationScope {
  id: string; proof_type: string; verified: boolean; active_testing_allowed: boolean; created_at: string;
}
export interface Asset {
  id: string; project_id: string; target_id: string; asset_type: string; value: string;
  metadata: Record<string, any>; first_seen: string; last_seen: string;
}
export interface Scan {
  id: string; target_id: string; scan_type: string; status: string; config: any; created_at: string;
  started_at: string | null; completed_at: string | null;
}
export interface ScanSchedule {
  id: string; target_id: string; scan_type: string; requested_modules: string[]; use_ai_planner: boolean;
  interval_minutes: number; enabled: boolean; next_run_at: string; last_run_at: string | null;
  last_scan_id: string | null; last_error: string | null; created_at: string;
}
// One registered scanner tool (GET /scan-capabilities/pipeline). `produces_vulnerabilities`
// is the important one for reading a report honestly: only nuclei/nuclei-dast can ever write
// a Vulnerability row -- every other tool inventories assets, so it running perfectly still
// adds nothing to the vulnerability list.
export interface PipelineTool {
  name: string;
  phase: number;
  capability: string;
  category: string;
  kill_chain_phase: string;
  safety_tier: string;
  requires_active_testing: boolean;
  applicable_target_types: string[] | null;
  produces_vulnerabilities: boolean;
  binary: string;
  // true/false as reported by the scan WORKER (the only process whose PATH matters);
  // null when no worker has reported yet -- unknown, which must not be shown as missing.
  binary_available: boolean | null;
  missing_requirements: string[];
}
export interface ToolRun {
  id: string; tool_name: string; tool_version: string; status: string; exit_code: number | null;
  raw_output_ref: string | null; started_at: string; completed_at: string | null;
  error_message: string | null; duration_seconds: number | null;
}
export interface Vulnerability {
  id: string; title: string; severity: string; status: string; category: string | null;
  cvss_score: number | null; cvss_vector: string | null; description: string | null; created_at: string;
  // Derived server-side (never stored): "detection" marks a technology/WAF/version
  // OBSERVATION rather than a weakness. Detections are excluded from the security score,
  // so the UI must distinguish them -- otherwise an open finding appears to count and
  // silently does not. Optional: older API responses omit it.
  classification?: "vulnerability" | "detection";
}
export interface RiskScore {
  final_risk_score: number | null; asset_criticality_weight: number; business_impact_score: number | null; rationale: string | null;
}
export interface ComplianceMapping {
  framework: string; framework_label: string; control_id: string; control_description: string | null;
}
export interface Remediation {
  summary: string | null; steps: string[]; references: { title: string; url: string }[]; generated_by: string;
}
export interface Report { id: string; type: string; format: string; generated_at: string; }
export interface AssistantAnswer {
  answer: string; model_version: string; prompt_version: string; grounded_in_vulnerability: boolean;
}
export interface AIStatus { enabled: boolean; model: string; }
export interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }
export interface RecentScan {
  id: string; project_id: string; project_name: string; target_value: string;
  scan_type: string; status: string; created_at: string;
}
export interface DashboardSummary {
  projects: number;
  targets: number;
  scans: { total: number; queued: number; running: number; completed: number; failed: number };
  vulnerabilities: { total: number; active: number; by_severity: SeverityCounts };
  recent_scans: RecentScan[];
}
export interface ApiKey {
  id: string; name: string; prefix: string; revoked: boolean; last_used_at: string | null; created_at: string;
}
export interface ApiKeyCreated extends ApiKey {
  secret: string;
}
export interface AuditEvent {
  id: string; actor_user_id: string | null; actor_email: string | null; action: string;
  resource_type: string; resource_id: string | null; detail: string | null; created_at: string;
}
export interface AppNotification {
  id: string; project_id: string | null; scan_id: string | null; type: string;
  severity: string; title: string; body: string | null; read: boolean; created_at: string;
}
export interface Recommendation {
  vulnerability_id: string; project_id: string; project_name: string; title: string;
  severity: string; cvss_score: number | null; category: string | null;
}
export interface Usage {
  plan_tier: string;
  plan_name: string;
  price_usd_month: number;
  usage: { projects: number; targets: number; scans_this_month: number };
  limits: { projects: number | null; targets: number | null; scans_per_month: number | null };
}
export interface PlanCatalogItem {
  tier: string; name: string; price_usd_month: number;
  max_projects: number | null; max_targets: number | null; max_scans_per_month: number | null;
}

// ---- Remediation workflow types ----
// `status` mirrors the backend lifecycle exactly (remediation/models.py). `verified` and
// `risk_accepted` are reachable only through the verification and risk-acceptance flows, never
// through the generic transition control -- see REMEDIATION_TRANSITION_TARGETS below.
export type RemediationStatus =
  | "proposed" | "accepted" | "in_progress" | "awaiting_verification"
  | "verified" | "closed" | "risk_accepted" | "rejected" | "reopened";
export type RemediationPriority = "critical" | "high" | "medium" | "low";

export interface RemediationItem {
  id: string;
  workspace_id: string;
  project_id: string;
  // scoring.issue_key -- the SAME identity the security score and the reports use, so one
  // issue at many locations is one item.
  issue_key: string;
  vulnerability_id: string | null;
  remediation_id: string | null;
  title: string;
  status: RemediationStatus;
  priority: RemediationPriority;
  assignee_user_id: string | null;
  due_date: string | null;
  notes: string | null;
  // "human" | "ai" -- provenance, so AI guidance is never displayed as human-authored.
  notes_source: string | null;
  source: string;
  resolved_at: string | null;
  verified_at: string | null;
  // Optimistic-lock token. Send it back on every mutation.
  version: number;
  created_at: string;
  updated_at: string;
}

export interface RemediationItemPatch {
  version: number;
  assignee_user_id?: string | null;
  // Explicit clear flags: an omitted field means "leave unchanged", so clearing needs its own
  // signal rather than overloading null.
  clear_assignee?: boolean;
  due_date?: string | null;
  clear_due_date?: boolean;
  priority?: RemediationPriority;
  notes?: string;
}

export interface RemediationEvent {
  id: string; remediation_item_id: string; event_type: string;
  from_status: string | null; to_status: string | null;
  actor_user_id: string | null; detail: string | null; created_at: string;
}

export interface RemediationEvidence {
  id: string; tool_run_id: string | null; evidence_type: string;
  storage_uri: string; checksum: string; uploaded_by: string | null; created_at: string;
}

export interface VerificationRequest {
  id: string; remediation_item_id: string; status: string;
  // null until a retest has actually been evaluated.
  result: "passed" | "failed" | null;
  scan_id: string | null; requested_by: string | null;
  claimed_at: string | null; completed_at: string | null;
  // The reproducible basis for the verdict: { scan_id, issue_key, live_locations, evaluated_at }.
  detail: Record<string, any>;
  created_at: string;
}

export interface RiskAcceptance {
  id: string; project_id: string; vulnerability_id: string; remediation_item_id: string | null;
  justification: string; accepted_by: string | null; approved_by: string | null;
  expires_at: string; review_due_at: string | null;
  status: "active" | "expired" | "revoked";
  revoked_by: string | null; revoked_at: string | null; revoke_reason: string | null;
  created_at: string;
}

export interface RiskAcceptanceCreate {
  vulnerability_id: string;
  justification: string;
  expires_at: string;
  review_due_at?: string;
  remediation_item_id?: string;
  version?: number;
}

export interface RemediationProgress {
  total: number; proposed: number; accepted: number; in_progress: number;
  awaiting_verification: number; verified: number; closed: number; risk_accepted: number;
  rejected: number; reopened: number; open: number; resolved: number; overdue: number;
  completion_percent: number;
}

// The only statuses the generic transition control may offer. Mirrors the backend's
// TransitionTarget literal: `verified` and `risk_accepted` are absent by design.
export const REMEDIATION_TRANSITION_TARGETS: RemediationStatus[] = [
  "accepted", "in_progress", "awaiting_verification", "closed", "reopened", "rejected", "proposed",
];
export const REMEDIATION_PRIORITIES: RemediationPriority[] = ["critical", "high", "medium", "low"];

// ---- Risk assessment types ----
export interface AssessmentTopRisk {
  title: string; severity: string;
  // null means "not scored", NOT zero -- rendered as N/A.
  max_risk: number | null; max_cvss: number | null; endpoint_count: number;
}

export interface AssessmentSummary {
  security_score: number;
  score_band: string;
  severity_counts: Record<string, number>;
  active_severity_counts: Record<string, number>;
  total_findings: number;
  active_findings: number;
  affected_assets: string[];
  affected_endpoint_count: number;
  unresolved_issue_count: number;
  top_risks: AssessmentTopRisk[];
  remediation_progress: RemediationProgress;
  risk_accepted_count: number;
}

export interface RiskAssessment {
  id: string; workspace_id: string; project_id: string | null;
  title: string; period_start: string; period_end: string;
  status: "draft" | "issued";
  // null while draft -- distinct from a score of 0.
  security_score: number | null;
  score_band: string | null;
  summary: Partial<AssessmentSummary>;
  narrative: string | null;
  // "system" | "ai" | "human"
  narrative_source: string | null;
  previous_assessment_id: string | null;
  report_id: string | null;
  created_by: string | null;
  issued_by: string | null;
  issued_at: string | null;
  created_at: string;
}

export interface AssessmentFinding {
  id: string; assessment_id: string; issue_key: string; vulnerability_id: string | null;
  // Every value below is a FROZEN copy taken at issue time. Never read through
  // vulnerability_id to today's row -- that would defeat the freeze.
  frozen_title: string;
  frozen_severity: string;
  frozen_cvss_score: number | null;
  frozen_final_risk_score: number | null;
  frozen_vulnerability_status: string;
  frozen_remediation_status: string | null;
  risk_accepted: boolean;
  location_count: number;
  created_at: string;
}

export interface AssessmentComparison {
  has_previous: boolean;
  previous_security_score?: number | null;
  // null = no basis for comparison; 0 = measured and unchanged. Do not collapse the two.
  security_score_delta?: number | null;
  direction?: "improved" | "declined" | "unchanged" | null;
  active_findings_delta?: number | null;
  unresolved_issue_delta?: number | null;
  critical_delta?: number | null;
  high_delta?: number | null;
  remediation_completion_delta?: number | null;
}
