// All API calls go through the Next.js proxy route (/api/proxy/*)
// so the browser never needs to know the backend's internal URL.
const BASE_URL = "/api/proxy";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("palauth_admin_token");
}

function setToken(token: string) {
  localStorage.setItem("palauth_admin_token", token);
}

function clearToken() {
  localStorage.removeItem("palauth_admin_token");
}

export function isTokenExpired(): boolean {
  const token = getToken();
  if (!token) return true;
  try {
    const payload = JSON.parse(atob(token.split(".")[1]));
    if (!payload.exp) return false;
    return Date.now() >= payload.exp * 1000;
  } catch {
    return true;
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401 && typeof window !== "undefined") {
    clearToken();
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(
      res.status,
      body.error ?? "unknown_error",
      body.error_description ?? "An unexpected error occurred"
    );
  }

  if (res.status === 204) {
    return undefined as T;
  }

  return res.json();
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public description: string
  ) {
    super(description);
    this.name = "ApiError";
  }
}

// --- Auth ---

export interface AdminLoginResponse {
  token: string;
}

export interface AdminSetupResponse {
  id: string;
  email: string;
  role: string;
  token: string;
}

export async function checkSetupDone(): Promise<boolean> {
  try {
    await request("/admin/setup", {
      method: "POST",
      body: JSON.stringify({}),
    });
    return false;
  } catch (err) {
    if (err instanceof ApiError && err.code === "admin_exists") {
      return true;
    }
    // email_required / password_required means no admin yet
    return false;
  }
}

export async function adminSetup(email: string, password: string) {
  const res = await request<AdminSetupResponse>("/admin/setup", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setToken(res.token);
  return res;
}

export async function adminLogin(email: string, password: string) {
  const res = await request<AdminLoginResponse>("/admin/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setToken(res.token);
  return res;
}

export function adminLogout() {
  clearToken();
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

// --- Projects ---

export interface ProjectConfig {
  email_verification_method: string;
  email_verification_ttl: number;
  password_min_length: number;
  password_max_length: number;
  mfa_enabled: boolean;
  session_idle_timeout: number;
  session_abs_timeout: number;
}

export interface Project {
  id: string;
  name: string;
  config: ProjectConfig;
  created_at: string;
  updated_at: string;
}

export interface ApiKey {
  id: string;
  project_id: string;
  key_type: string;
  prefix: string;
  plaintext?: string;
  created_at: string;
}

export interface CreateProjectResponse {
  project: Project;
  api_keys: ApiKey[];
}

export async function listProjects() {
  return request<Project[]>("/admin/projects");
}

export async function getProject(id: string) {
  return request<Project>(`/admin/projects/${id}`);
}

export async function createProject(
  name: string,
  config?: Partial<ProjectConfig>
) {
  return request<CreateProjectResponse>("/admin/projects", {
    method: "POST",
    body: JSON.stringify({ name, config }),
  });
}

export async function updateProject(
  id: string,
  name: string,
  config?: ProjectConfig
) {
  return request<Project>(`/admin/projects/${id}/config`, {
    method: "PUT",
    body: JSON.stringify({ name, config }),
  });
}

export async function deleteProject(id: string) {
  return request<void>(`/admin/projects/${id}`, { method: "DELETE" });
}

// --- API Keys ---

export async function listKeys(projectId: string) {
  return request<ApiKey[]>(`/admin/projects/${projectId}/keys`);
}

export async function rotateKey(projectId: string, keyType: string) {
  return request<{ new_key: string }>(
    `/admin/projects/${projectId}/keys/rotate`,
    {
      method: "POST",
      body: JSON.stringify({ key_type: keyType }),
    }
  );
}

// --- Users ---

export interface User {
  id: string;
  project_id: string;
  email: string;
  email_verified: boolean;
  banned: boolean;
  ban_reason?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  last_login_at?: string;
}

export interface UserListResponse {
  users: User[];
  next_cursor?: {
    created_at: string;
    id: string;
  };
}

export interface UserListParams {
  limit?: number;
  cursor_created_at?: string;
  cursor_id?: string;
  banned?: string;
  email?: string;
}

export async function listUsers(projectId: string, params?: UserListParams) {
  const query = new URLSearchParams();
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.cursor_created_at)
    query.set("cursor_created_at", params.cursor_created_at);
  if (params?.cursor_id) query.set("cursor_id", params.cursor_id);
  if (params?.banned) query.set("banned", params.banned);
  if (params?.email) query.set("email", params.email);

  const qs = query.toString();
  return request<UserListResponse>(
    `/admin/projects/${projectId}/users${qs ? `?${qs}` : ""}`
  );
}

export async function getUser(projectId: string, userId: string) {
  return request<User>(`/admin/projects/${projectId}/users/${userId}`);
}

export async function createUser(
  projectId: string,
  email: string,
  password?: string
) {
  return request<User>(`/admin/projects/${projectId}/users`, {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function updateUser(
  projectId: string,
  userId: string,
  data: { email_verified?: boolean; metadata?: Record<string, unknown> }
) {
  return request<User>(`/admin/projects/${projectId}/users/${userId}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deleteUser(projectId: string, userId: string) {
  return request<void>(`/admin/projects/${projectId}/users/${userId}`, {
    method: "DELETE",
  });
}

export async function banUser(
  projectId: string,
  userId: string,
  reason: string
) {
  return request<{ status: string }>(
    `/admin/projects/${projectId}/users/${userId}/ban`,
    {
      method: "POST",
      body: JSON.stringify({ reason }),
    }
  );
}

export async function unbanUser(projectId: string, userId: string) {
  return request<{ status: string }>(
    `/admin/projects/${projectId}/users/${userId}/unban`,
    { method: "POST" }
  );
}

export async function resetUserPassword(projectId: string, userId: string) {
  return request<{ success: boolean }>(
    `/admin/projects/${projectId}/users/${userId}/reset-password`,
    { method: "POST" }
  );
}

// --- Analytics ---

export interface ProjectAnalytics {
  total_users: number;
  active_sessions: number;
  mau: number;
}

export async function getProjectAnalytics(projectId: string) {
  return request<ProjectAnalytics>(
    `/admin/projects/${projectId}/analytics`
  );
}

// --- Audit Logs ---

export interface AuditLogEntry {
  id: string;
  project_id: string;
  event_type: string;
  target_type: string;
  target_id: string;
  actor_id: string;
  auth_method: string;
  metadata?: Record<string, unknown>;
  hash: string;
  prev_hash: string;
  created_at: string;
}

export interface AuditLogListResponse {
  entries: AuditLogEntry[];
  next_cursor?: {
    created_at: string;
    id: string;
  };
}

export interface AuditLogListParams {
  limit?: number;
  event_type?: string;
  cursor_time?: string;
  cursor_id?: string;
}

export async function listAuditLogs(
  projectId: string,
  params?: AuditLogListParams
) {
  const query = new URLSearchParams();
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.event_type) query.set("event_type", params.event_type);
  if (params?.cursor_time) query.set("cursor_time", params.cursor_time);
  if (params?.cursor_id) query.set("cursor_id", params.cursor_id);

  const qs = query.toString();
  return request<AuditLogListResponse>(
    `/admin/projects/${projectId}/audit-logs${qs ? `?${qs}` : ""}`
  );
}

export interface VerifyResult {
  valid: boolean;
  total_entries: number;
  verified_entries: number;
  broken_at_index?: number;
  broken_at_id?: string;
}

export async function verifyAuditLogs(projectId: string) {
  return request<VerifyResult>(
    `/admin/projects/${projectId}/audit-logs/verify`,
    { method: "POST" }
  );
}

export async function exportAuditLogs(
  projectId: string,
  format: "json" | "csv"
) {
  const token = getToken();
  const res = await fetch(
    `${BASE_URL}/admin/projects/${projectId}/audit-logs/export?format=${format}`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) throw new Error("Export failed");
  return res.blob();
}
