import type {
  PalAuthClientConfig,
  AuthResult,
  TokenResponse,
  Session,
  PalAuthErrorBody,
  SignupParams,
  SignInParams,
  VerifyEmailParams,
  PasswordResetParams,
  PasswordResetConfirmParams,
  PasswordChangeParams,
} from "./types.js";

/** Validates that a path parameter does not contain path traversal characters. */
function validatePathParam(name: string, value: string): void {
  if (value.includes("/") || value.includes("..") || value.includes("%")) {
    throw new Error(`Invalid ${name}: must not contain path separators`);
  }
}

/** Error thrown by PalAuth API calls. */
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

/** PalAuth client for browser and Node.js applications. */
export class PalAuthClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly fetchFn: typeof globalThis.fetch;

  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private refreshPromise: Promise<TokenResponse> | null = null;
  private tokenChangeCallback: ((tokens: { accessToken: string | null; refreshToken: string | null }) => void) | null = null;

  constructor(config: PalAuthClientConfig) {
    this.baseUrl = config.url.replace(/\/+$/, "");
    this.apiKey = config.apiKey;
    this.fetchFn = config.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Register a new user. */
  async signUp(params: SignupParams): Promise<AuthResult> {
    const result = await this.request<AuthResult>("POST", "/auth/signup", params);
    this.setTokens(result.access_token, result.refresh_token);
    return result;
  }

  /** Authenticate with email and password. */
  async signIn(params: SignInParams): Promise<AuthResult> {
    const result = await this.request<AuthResult>("POST", "/auth/login", params);
    this.setTokens(result.access_token, result.refresh_token);
    return result;
  }

  /** Verify email address. */
  async verifyEmail(params: VerifyEmailParams): Promise<{ status: string }> {
    return this.request("POST", "/auth/verify-email", params);
  }

  /** Resend email verification. */
  async resendVerification(email: string): Promise<{ verification_token?: string; verification_code?: string }> {
    return this.request("POST", "/auth/resend-verification", { email });
  }

  /** Request a password reset. Always succeeds (enumeration prevention). */
  async requestPasswordReset(params: PasswordResetParams): Promise<{ success: boolean }> {
    return this.request("POST", "/auth/password/reset", params);
  }

  /** Confirm password reset with token. */
  async confirmPasswordReset(params: PasswordResetConfirmParams): Promise<{ success: boolean }> {
    return this.request("POST", "/auth/password/reset/confirm", params);
  }

  /** Change password (requires authentication). */
  async changePassword(params: PasswordChangeParams): Promise<{ success: boolean }> {
    return this.authenticatedRequest("POST", "/auth/password/change", params);
  }

  /** Refresh the access token using the stored refresh token. */
  async refresh(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error("No refresh token available");
    }

    // Deduplicate concurrent refresh calls.
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = this.request<TokenResponse>("POST", "/auth/token/refresh", {
      refresh_token: this.refreshToken,
    });

    try {
      const result = await this.refreshPromise;
      this.setTokens(result.access_token, result.refresh_token);
      return result;
    } finally {
      this.refreshPromise = null;
    }
  }

  /** List active sessions. */
  async listSessions(): Promise<Session[]> {
    const result = await this.authenticatedRequest<{ sessions: Session[] }>("GET", "/auth/sessions");
    return result.sessions;
  }

  /** Revoke a specific session. */
  async revokeSession(sessionId: string): Promise<void> {
    validatePathParam("sessionId", sessionId);
    await this.authenticatedRequest("DELETE", `/auth/sessions/${sessionId}`);
  }

  /** Revoke all sessions. */
  async revokeAllSessions(): Promise<void> {
    await this.authenticatedRequest("DELETE", "/auth/sessions");
  }

  /** Logout (revoke current session). */
  async signOut(): Promise<void> {
    await this.authenticatedRequest("POST", "/auth/logout");
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenChangeCallback?.({ accessToken: null, refreshToken: null });
  }

  /** Get the current access token (or null). */
  getAccessToken(): string | null {
    return this.accessToken;
  }

  /**
   * Set a callback that fires whenever tokens change (after login, signup, refresh, or logout).
   * Use this for secure token persistence (e.g., encrypted storage).
   */
  onTokenChange(callback: (tokens: { accessToken: string | null; refreshToken: string | null }) => void): void {
    this.tokenChangeCallback = callback;
  }

  /** Manually set tokens (e.g., restoring from secure storage). */
  setTokens(accessToken: string, refreshToken: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenChangeCallback?.({ accessToken, refreshToken });
  }

  /** Make an authenticated request, auto-refreshing on 401. */
  private async authenticatedRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
    try {
      return await this.request<T>(method, path, body, true);
    } catch (err) {
      if (err instanceof PalAuthError && err.status === 401 && this.refreshToken) {
        await this.refresh();
        return this.request<T>(method, path, body, true);
      }
      throw err;
    }
  }

  /** Make an HTTP request to the PalAuth server. */
  private async request<T>(method: string, path: string, body?: unknown, auth = false): Promise<T> {
    const headers: Record<string, string> = {
      "X-API-Key": this.apiKey,
      "Content-Type": "application/json",
    };

    if (auth && this.accessToken) {
      headers["Authorization"] = `Bearer ${this.accessToken}`;
    }

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

    return response.json() as Promise<T>;
  }
}
