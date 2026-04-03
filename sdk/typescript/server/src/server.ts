import type {
  PalAuthServerConfig,
  TokenInfo,
  UserDetail,
  UserListResult,
  UserListOptions,
  PalAuthErrorBody,
} from "./types.js";

/** Validates that a path parameter does not contain path traversal characters. */
function validatePathParam(name: string, value: string): void {
  if (value.includes("/") || value.includes("..") || value.includes("%")) {
    throw new Error(`Invalid ${name}: must not contain path separators`);
  }
}

/** Error thrown by PalAuth server SDK calls. */
export class PalAuthError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly requestId: string;

  constructor(body: PalAuthErrorBody) {
    super(body.error_description);
    this.name = "PalAuthError";
    this.code = body.error;
    this.status = body.status;
    this.requestId = body.request_id;
  }
}

/** PalAuth server SDK for backend services. */
export class PalAuthServer {
  private readonly baseUrl: string;
  private readonly serviceKey: string;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(config: PalAuthServerConfig) {
    this.baseUrl = config.url.replace(/\/+$/, "");
    this.serviceKey = config.serviceKey;
    this.fetchFn = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Verify and introspect an access token. */
  async verifyToken(token: string): Promise<TokenInfo> {
    return this.request<TokenInfo>("POST", "/oauth/introspect", { token });
  }

  /** Get a user by ID. Requires project context from the service key. */
  async getUser(projectId: string, userId: string): Promise<UserDetail> {
    validatePathParam("projectId", projectId);
    validatePathParam("userId", userId);
    return this.request<UserDetail>("GET", `/admin/projects/${projectId}/users/${userId}`);
  }

  /** List users in a project. */
  async listUsers(projectId: string, options?: UserListOptions): Promise<UserListResult> {
    validatePathParam("projectId", projectId);
    const params = new URLSearchParams();
    if (options?.limit) params.set("limit", String(options.limit));
    if (options?.cursor_created_at) params.set("cursor_created_at", options.cursor_created_at);
    if (options?.cursor_id) params.set("cursor_id", options.cursor_id);
    if (options?.banned !== undefined) params.set("banned", String(options.banned));
    if (options?.email) params.set("email", options.email);

    const qs = params.toString();
    const path = `/admin/projects/${projectId}/users${qs ? `?${qs}` : ""}`;
    return this.request<UserListResult>("GET", path);
  }

  /** Revoke a token (RFC 7009). */
  async revokeToken(token: string, tokenTypeHint?: string): Promise<void> {
    await this.request("POST", "/oauth/revoke", { token, token_type_hint: tokenTypeHint });
  }

  /** Make an HTTP request to the PalAuth server. */
  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "X-API-Key": this.serviceKey,
      "Content-Type": "application/json",
    };

    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      let errorBody: PalAuthErrorBody;
      try {
        errorBody = await response.json();
      } catch {
        errorBody = {
          error: "unknown_error",
          error_description: `HTTP ${response.status}`,
          status: response.status,
          request_id: "",
        };
      }
      throw new PalAuthError(errorBody);
    }

    const text = await response.text();
    if (!text) return {} as T;
    return JSON.parse(text) as T;
  }
}
