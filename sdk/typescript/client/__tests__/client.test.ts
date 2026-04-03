import { describe, it, expect, vi, beforeEach } from "vitest";
import { PalAuthClient, PalAuthError } from "../src/client.js";
import type { PalAuthClientConfig } from "../src/types.js";

function createMockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0;
  const mockFn = vi.fn(async (_url: string, _init?: RequestInit) => {
    const resp = responses[callIndex++];
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: async () => resp.body,
      text: async () => JSON.stringify(resp.body),
    } as Response;
  });
  return mockFn;
}

function createClient(fetchFn: ReturnType<typeof createMockFetch>): PalAuthClient {
  const config: PalAuthClientConfig = {
    url: "https://auth.example.com",
    apiKey: "pk_test_abc123",
    fetch: fetchFn as unknown as typeof globalThis.fetch,
  };
  return new PalAuthClient(config);
}

describe("PalAuthClient", () => {
  describe("constructor", () => {
    it("creates an instance", () => {
      const fetchFn = createMockFetch([]);
      const client = createClient(fetchFn);
      expect(client).toBeInstanceOf(PalAuthClient);
    });

    it("strips trailing slashes from URL", () => {
      const fetchFn = createMockFetch([
        { status: 200, body: { access_token: "at", refresh_token: "rt", token_type: "Bearer", expires_in: 1800, user: { id: "usr_1", email: "a@b.com", email_verified: false, created_at: "2026-01-01" } } },
      ]);
      const client = new PalAuthClient({
        url: "https://auth.example.com///",
        apiKey: "pk_test_abc",
        fetch: fetchFn as unknown as typeof globalThis.fetch,
      });
      client.signUp({ email: "a@b.com", password: "test-pass-123456" });
      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/auth/signup",
        expect.anything()
      );
    });
  });

  describe("signUp", () => {
    it("sends correct request and stores tokens", async () => {
      const responseBody = {
        access_token: "access_123",
        refresh_token: "refresh_123",
        token_type: "Bearer",
        expires_in: 1800,
        user: { id: "usr_1", email: "user@test.com", email_verified: false, created_at: "2026-01-01T00:00:00Z" },
      };
      const fetchFn = createMockFetch([{ status: 201, body: responseBody }]);
      const client = createClient(fetchFn);

      let savedTokens: { accessToken: string | null; refreshToken: string | null } | null = null;
      client.onTokenChange((tokens) => { savedTokens = tokens; });

      const result = await client.signUp({ email: "user@test.com", password: "super-secure-pass-123" });

      expect(result.access_token).toBe("access_123");
      expect(result.user.email).toBe("user@test.com");
      expect(client.getAccessToken()).toBe("access_123");
      expect(savedTokens?.refreshToken).toBe("refresh_123");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/auth/signup",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-API-Key": "pk_test_abc123",
            "Content-Type": "application/json",
          }),
          body: JSON.stringify({ email: "user@test.com", password: "super-secure-pass-123" }),
        })
      );
    });

    it("throws PalAuthError on failure", async () => {
      const fetchFn = createMockFetch([{
        status: 400,
        body: { error: "password_too_short", error_description: "Password must be at least 15 characters", status: 400, request_id: "req_1" },
      }]);
      const client = createClient(fetchFn);

      await expect(client.signUp({ email: "a@b.com", password: "short" }))
        .rejects.toThrow(PalAuthError);

      try {
        await client.signUp({ email: "a@b.com", password: "short" });
      } catch (err) {
        // Already thrown above, this is for the earlier assertion
      }
    });
  });

  describe("signIn", () => {
    it("sends correct request and stores tokens", async () => {
      const responseBody = {
        access_token: "at_login",
        refresh_token: "rt_login",
        token_type: "Bearer",
        expires_in: 1800,
        user: { id: "usr_2", email: "user@test.com", email_verified: true, created_at: "2026-01-01T00:00:00Z" },
      };
      const fetchFn = createMockFetch([{ status: 200, body: responseBody }]);
      const client = createClient(fetchFn);

      const result = await client.signIn({ email: "user@test.com", password: "super-secure-pass-123" });

      expect(result.access_token).toBe("at_login");
      expect(result.user.id).toBe("usr_2");
      expect(client.getAccessToken()).toBe("at_login");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/auth/login",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ email: "user@test.com", password: "super-secure-pass-123" }),
        })
      );
    });
  });

  describe("auto-refresh on 401", () => {
    it("refreshes token and retries on 401", async () => {
      const fetchFn = createMockFetch([
        // First call: listSessions → 401
        { status: 401, body: { error: "token_expired", error_description: "expired", status: 401, request_id: "req_1" } },
        // Refresh call → success
        { status: 200, body: { access_token: "new_at", refresh_token: "new_rt", token_type: "Bearer", expires_in: 1800 } },
        // Retry listSessions → success
        { status: 200, body: { sessions: [] } },
      ]);
      const client = createClient(fetchFn);
      client.setTokens("old_at", "old_rt");

      let savedTokens: { accessToken: string | null; refreshToken: string | null } | null = null;
      client.onTokenChange((tokens) => { savedTokens = tokens; });

      const sessions = await client.listSessions();

      expect(sessions).toEqual([]);
      expect(client.getAccessToken()).toBe("new_at");
      expect(savedTokens?.refreshToken).toBe("new_rt");
      expect(fetchFn).toHaveBeenCalledTimes(3);
    });

    it("throws if no refresh token available on 401", async () => {
      const fetchFn = createMockFetch([
        { status: 401, body: { error: "unauthorized", error_description: "no token", status: 401, request_id: "req_1" } },
      ]);
      const client = createClient(fetchFn);
      // No tokens set

      await expect(client.listSessions()).rejects.toThrow(PalAuthError);
    });
  });

  describe("verifyEmail", () => {
    it("sends token-based verification", async () => {
      const fetchFn = createMockFetch([{ status: 200, body: { status: "verified" } }]);
      const client = createClient(fetchFn);

      const result = await client.verifyEmail({ token: "vt_123" });
      expect(result.status).toBe("verified");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/auth/verify-email",
        expect.objectContaining({
          body: JSON.stringify({ token: "vt_123" }),
        })
      );
    });
  });

  describe("signOut", () => {
    it("clears stored tokens and notifies callback", async () => {
      const fetchFn = createMockFetch([{ status: 200, body: { success: true } }]);
      const client = createClient(fetchFn);
      client.setTokens("at", "rt");

      let savedTokens: { accessToken: string | null; refreshToken: string | null } | null = null;
      client.onTokenChange((tokens) => { savedTokens = tokens; });

      await client.signOut();

      expect(client.getAccessToken()).toBeNull();
      expect(savedTokens?.accessToken).toBeNull();
      expect(savedTokens?.refreshToken).toBeNull();
    });
  });

  describe("password operations", () => {
    it("requestPasswordReset always succeeds", async () => {
      const fetchFn = createMockFetch([{ status: 200, body: { success: true } }]);
      const client = createClient(fetchFn);

      const result = await client.requestPasswordReset({ email: "user@test.com" });
      expect(result.success).toBe(true);
    });

    it("confirmPasswordReset sends token and new password", async () => {
      const fetchFn = createMockFetch([{ status: 200, body: { success: true } }]);
      const client = createClient(fetchFn);

      await client.confirmPasswordReset({ token: "rst_123", new_password: "new-super-secure-pass-123" });

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/auth/password/reset/confirm",
        expect.objectContaining({
          body: JSON.stringify({ token: "rst_123", new_password: "new-super-secure-pass-123" }),
        })
      );
    });
  });

  describe("path parameter validation", () => {
    it("rejects session ID with path traversal", async () => {
      const fetchFn = createMockFetch([]);
      const client = createClient(fetchFn);
      client.setTokens("at", "rt");

      await expect(client.revokeSession("../../admin/projects/prj_1"))
        .rejects.toThrow("Invalid sessionId: must not contain path separators");
    });

    it("rejects session ID with slash", async () => {
      const fetchFn = createMockFetch([]);
      const client = createClient(fetchFn);
      client.setTokens("at", "rt");

      await expect(client.revokeSession("foo/bar"))
        .rejects.toThrow("Invalid sessionId: must not contain path separators");
    });

    it("rejects session ID with percent encoding", async () => {
      const fetchFn = createMockFetch([]);
      const client = createClient(fetchFn);
      client.setTokens("at", "rt");

      await expect(client.revokeSession("foo%2Fbar"))
        .rejects.toThrow("Invalid sessionId: must not contain path separators");
    });
  });

  describe("PalAuthError", () => {
    it("has correct properties", () => {
      const err = new PalAuthError({
        error: "invalid_credentials",
        error_description: "Email or password is incorrect",
        status: 401,
        request_id: "req_abc",
      });

      expect(err.code).toBe("invalid_credentials");
      expect(err.message).toBe("Email or password is incorrect");
      expect(err.status).toBe(401);
      expect(err.requestId).toBe("req_abc");
      expect(err.name).toBe("PalAuthError");
    });
  });
});
