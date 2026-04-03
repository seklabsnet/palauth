import { describe, it, expect, vi } from "vitest";
import { PalAuthServer, PalAuthError } from "../src/server.js";
import type { PalAuthServerConfig } from "../src/types.js";

function createMockFetch(responses: Array<{ status: number; body: unknown }>) {
  let callIndex = 0;
  const mockFn = vi.fn(async (_url: string, _init?: RequestInit) => {
    const resp = responses[callIndex++];
    const bodyStr = JSON.stringify(resp.body);
    return {
      ok: resp.status >= 200 && resp.status < 300,
      status: resp.status,
      json: async () => resp.body,
      text: async () => bodyStr,
    } as Response;
  });
  return mockFn;
}

function createServer(fetchFn: ReturnType<typeof createMockFetch>): PalAuthServer {
  const config: PalAuthServerConfig = {
    url: "https://auth.example.com",
    serviceKey: "sk_test_secret",
    fetch: fetchFn as unknown as typeof globalThis.fetch,
  };
  return new PalAuthServer(config);
}

describe("PalAuthServer", () => {
  describe("verifyToken", () => {
    it("sends introspect request and returns result", async () => {
      const fetchFn = createMockFetch([{
        status: 200,
        body: { active: true, sub: "usr_123", project_id: "prj_1", token_type: "Bearer", exp: 9999999999, iat: 1000000000 },
      }]);
      const server = createServer(fetchFn);

      const result = await server.verifyToken("some.jwt.token");

      expect(result.active).toBe(true);
      expect(result.sub).toBe("usr_123");
      expect(result.project_id).toBe("prj_1");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/oauth/introspect",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "X-API-Key": "sk_test_secret",
          }),
          body: JSON.stringify({ token: "some.jwt.token" }),
        })
      );
    });

    it("returns inactive for invalid token", async () => {
      const fetchFn = createMockFetch([{
        status: 200,
        body: { active: false },
      }]);
      const server = createServer(fetchFn);

      const result = await server.verifyToken("invalid.token");
      expect(result.active).toBe(false);
    });
  });

  describe("getUser", () => {
    it("fetches user by project and user ID", async () => {
      const fetchFn = createMockFetch([{
        status: 200,
        body: {
          id: "usr_1", project_id: "prj_1", email: "user@test.com",
          email_verified: true, banned: false, metadata: {}, active_sessions: 2,
          created_at: "2026-01-01T00:00:00Z",
        },
      }]);
      const server = createServer(fetchFn);

      const user = await server.getUser("prj_1", "usr_1");

      expect(user.id).toBe("usr_1");
      expect(user.email).toBe("user@test.com");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/admin/projects/prj_1/users/usr_1",
        expect.objectContaining({ method: "GET" })
      );
    });

    it("throws PalAuthError on 404", async () => {
      const fetchFn = createMockFetch([{
        status: 404,
        body: { error: "not_found", error_description: "User not found", status: 404, request_id: "req_1" },
      }]);
      const server = createServer(fetchFn);

      await expect(server.getUser("prj_1", "usr_missing"))
        .rejects.toThrow(PalAuthError);
    });
  });

  describe("listUsers", () => {
    it("lists users with query parameters", async () => {
      const fetchFn = createMockFetch([{
        status: 200,
        body: {
          users: [{ id: "usr_1", project_id: "prj_1", email: "a@b.com", email_verified: true, banned: false, metadata: {}, active_sessions: 0, created_at: "2026-01-01T00:00:00Z" }],
          total: 1,
        },
      }]);
      const server = createServer(fetchFn);

      const result = await server.listUsers("prj_1", { limit: 10, email: "a@b.com" });

      expect(result.users).toHaveLength(1);
      expect(result.total).toBe(1);

      const calledUrl = fetchFn.mock.calls[0][0] as string;
      expect(calledUrl).toContain("limit=10");
      expect(calledUrl).toContain("email=a%40b.com");
    });

    it("works without options", async () => {
      const fetchFn = createMockFetch([{
        status: 200,
        body: { users: [], total: 0 },
      }]);
      const server = createServer(fetchFn);

      const result = await server.listUsers("prj_1");
      expect(result.users).toHaveLength(0);
    });
  });

  describe("revokeToken", () => {
    it("sends revoke request", async () => {
      const fetchFn = createMockFetch([{ status: 200, body: {} }]);
      const server = createServer(fetchFn);

      await server.revokeToken("some_token", "refresh_token");

      expect(fetchFn).toHaveBeenCalledWith(
        "https://auth.example.com/oauth/revoke",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ token: "some_token", token_type_hint: "refresh_token" }),
        })
      );
    });
  });

  describe("path parameter validation", () => {
    it("rejects projectId with path traversal", async () => {
      const fetchFn = createMockFetch([]);
      const server = createServer(fetchFn);

      await expect(server.getUser("../../evil", "usr_1"))
        .rejects.toThrow("Invalid projectId: must not contain path separators");
    });

    it("rejects userId with slash", async () => {
      const fetchFn = createMockFetch([]);
      const server = createServer(fetchFn);

      await expect(server.getUser("prj_1", "usr/evil"))
        .rejects.toThrow("Invalid userId: must not contain path separators");
    });

    it("rejects listUsers with malicious projectId", async () => {
      const fetchFn = createMockFetch([]);
      const server = createServer(fetchFn);

      await expect(server.listUsers("../evil"))
        .rejects.toThrow("Invalid projectId: must not contain path separators");
    });
  });

  describe("PalAuthError", () => {
    it("has correct properties", () => {
      const err = new PalAuthError({
        error: "not_found",
        error_description: "User not found",
        status: 404,
        request_id: "req_xyz",
      });

      expect(err.code).toBe("not_found");
      expect(err.message).toBe("User not found");
      expect(err.status).toBe(404);
      expect(err.requestId).toBe("req_xyz");
    });
  });
});
