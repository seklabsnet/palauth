/** Configuration for PalAuth server SDK. */
export interface PalAuthServerConfig {
  /** Base URL of the PalAuth server (e.g. "https://auth.example.com"). */
  url: string;
  /** Secret API key (sk_test_* or sk_live_*). */
  serviceKey: string;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
}

/** Token introspection result. */
export interface TokenInfo {
  active: boolean;
  sub?: string;
  scope?: string;
  exp?: number;
  iat?: number;
  project_id?: string;
  token_type?: string;
  jti?: string;
}

/** User details returned by admin API. */
export interface UserDetail {
  id: string;
  project_id: string;
  email: string;
  email_verified: boolean;
  banned: boolean;
  ban_reason?: string;
  metadata?: Record<string, unknown>;
  active_sessions: number;
  last_login_at?: string;
  created_at: string;
  updated_at?: string;
}

/** Paginated user list result. */
export interface UserListResult {
  users: UserDetail[];
  next_cursor?: {
    created_at: string;
    id: string;
  };
  total: number;
}

/** User list query options. */
export interface UserListOptions {
  limit?: number;
  cursor_created_at?: string;
  cursor_id?: string;
  banned?: boolean;
  email?: string;
}

/** PalAuth server API error. */
export interface PalAuthErrorBody {
  error: string;
  error_description: string;
  status: number;
  request_id: string;
}
