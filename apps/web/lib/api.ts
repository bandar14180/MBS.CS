// Browser-side API client for MBS.SC. Handles bearer auth, one-shot refresh on
// 401, and workspace-scoped URLs. Tokens + current workspace live in localStorage.
const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000") + "/api/v1";

const ACCESS_KEY = "mbs_access";
const REFRESH_KEY = "mbs_refresh";
const WORKSPACE_KEY = "mbs_workspace";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export const tokens = {
  get access() {
    return typeof window === "undefined" ? null : localStorage.getItem(ACCESS_KEY);
  },
  get refresh() {
    return typeof window === "undefined" ? null : localStorage.getItem(REFRESH_KEY);
  },
  set(access: string, refresh: string) {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(WORKSPACE_KEY);
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
  return fetch(API_BASE + path, { ...init, headers });
}

async function tryRefresh(): Promise<boolean> {
  const refresh = tokens.refresh;
  if (!refresh) return false;
  const res = await rawFetch("/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: refresh }) }, false);
  if (!res.ok) return false;
  const data = await parse(res);
  tokens.set(data.access_token, data.refresh_token);
  return true;
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
  logout: (refresh_token: string) => api("/auth/logout", { method: "POST", body: { refresh_token } }),
  me: () => api<User>("/users/me"),
};

// ---- Workspaces ----
export const workspaceApi = {
  list: () => api<Workspace[]>("/workspaces"),
  create: (name: string) => api<Workspace>("/workspaces", { method: "POST", body: { name } }),
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
  list: (pid: string) => api<Scan[]>(ws(`/projects/${pid}/scans`)),
  create: (pid: string, target_id: string, scan_type: string, requested_modules: string[], use_ai_planner: boolean) =>
    api<Scan>(ws(`/projects/${pid}/scans`), {
      method: "POST",
      body: { target_id, scan_type, requested_modules, use_ai_planner },
    }),
  get: (pid: string, sid: string) => api<Scan>(ws(`/projects/${pid}/scans/${sid}`)),
  toolRuns: (pid: string, sid: string) => api<ToolRun[]>(ws(`/projects/${pid}/scans/${sid}/tool-runs`)),
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

// ---- Types ----
export interface User { id: string; email: string; full_name: string; }
export interface Workspace { id: string; name: string; plan_tier: string; }
export interface Project { id: string; name: string; description: string | null; status: string; created_at: string; }
export interface Target { id: string; type: string; value: string; criticality: string; created_at: string; }
export interface AuthorizationScope {
  id: string; proof_type: string; verified: boolean; active_testing_allowed: boolean; created_at: string;
}
export interface Scan {
  id: string; target_id: string; scan_type: string; status: string; config: any; created_at: string;
  started_at: string | null; completed_at: string | null;
}
export interface ToolRun {
  id: string; tool_name: string; tool_version: string; status: string; exit_code: number | null; raw_output_ref: string | null;
}
export interface Vulnerability {
  id: string; title: string; severity: string; status: string; category: string | null;
  cvss_score: number | null; cvss_vector: string | null; description: string | null; created_at: string;
}
export interface RiskScore {
  final_risk_score: number | null; asset_criticality_weight: number; business_impact_score: number | null; rationale: string | null;
}
export interface ComplianceMapping { framework: string; control_id: string; control_description: string | null; }
export interface Remediation {
  summary: string | null; steps: string[]; references: { title: string; url: string }[]; generated_by: string;
}
export interface Report { id: string; type: string; format: string; generated_at: string; }
