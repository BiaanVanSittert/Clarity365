import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getExoAccessToken, getExoAppOnlyAccess, invalidateExoAppAccessCache, invokeExoCommand, resetExoTokenStateForTests, resolveLatestExoRefreshToken, testExoConnectivity } from "./exo-client";
import { Tenant } from "../types";

// Refresh-token handling for Exchange Online (the "stale in-memory EXO
// refresh token" gap in ai-context-vault/Optimization/Optimization Plan.md).
// Only the network boundary (global fetch) is mocked.

function creds(refreshToken: string): Tenant["credentials"] {
  return { tenantId: "tenant-1", clientId: "c", authMode: "secret", exoRefreshToken: refreshToken } as Tenant["credentials"];
}

// expires_in 1 second: under the 5-minute safety margin, so every call
// refreshes instead of hitting the access-token cache.
function tokenResponse(accessToken: string, refreshToken: string) {
  return new Response(JSON.stringify({ access_token: accessToken, refresh_token: refreshToken, expires_in: 1 }), { status: 200 });
}

const sentRefreshToken = (call: unknown[]) => new URLSearchParams(String((call[1] as RequestInit).body)).get("refresh_token");

describe("getExoAccessToken refresh-token rotation", () => {
  const originalFetch = global.fetch;
  beforeEach(() => resetExoTokenStateForTests());
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("forwards a caller still holding a rotated-away token to the newest one", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(tokenResponse("access-1", "rt-b")).mockResolvedValueOnce(tokenResponse("access-2", "rt-c"));
    global.fetch = fetchMock as any;
    const rotated: string[] = [];

    await getExoAccessToken(creds("rt-a"), (t) => rotated.push(t));
    // Same stale tenant object, still carrying rt-a.
    const second = await getExoAccessToken(creds("rt-a"), (t) => rotated.push(t));

    expect(second.token).toBe("access-2");
    expect(sentRefreshToken(fetchMock.mock.calls[1])).toBe("rt-b");
    expect(rotated).toEqual(["rt-b", "rt-c"]);
    expect(resolveLatestExoRefreshToken("rt-a")).toBe("rt-c");
  });

  it("shares one refresh between parallel callers instead of redeeming the token several times", async () => {
    let resolveFetch: (r: Response) => void = () => {};
    const fetchMock = vi.fn().mockImplementation(() => new Promise<Response>((r) => (resolveFetch = r)));
    global.fetch = fetchMock as any;

    const calls = [getExoAccessToken(creds("rt-a")), getExoAccessToken(creds("rt-a")), getExoAccessToken(creds("rt-a"))];
    resolveFetch(tokenResponse("access-1", "rt-b"));
    const results = await Promise.all(calls);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(results.map((r) => r.token)).toEqual(["access-1", "access-1", "access-1"]);
  });

  it("uses a brand-new token from a reconnect as-is, never an older chain", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(tokenResponse("access-1", "rt-b")).mockResolvedValueOnce(tokenResponse("access-2", "rt-z2"));
    global.fetch = fetchMock as any;

    await getExoAccessToken(creds("rt-a"));
    await getExoAccessToken(creds("rt-z"));

    expect(sentRefreshToken(fetchMock.mock.calls[1])).toBe("rt-z");
  });
});

// App-only access (Exchange.ManageAsApp + an Entra role, no sign-in) - see
// ai-context-vault/Optimization/Exchange App-Only Access Plan.md.
describe("app-only Exchange access", () => {
  const originalFetch = global.fetch;
  const GLOBAL_READER = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
  const fakeJwt = (claims: object) => `x.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.y`;
  const tenant = (extra: object = {}) =>
    ({
      id: "t1",
      credentials: { tenantId: "tenant-app", clientId: "app-1", clientSecret: "secret", authMode: "secret", ...extra },
    }) as any;
  const tokenFor = (claims: object) => new Response(JSON.stringify({ access_token: fakeJwt(claims), expires_in: 3600 }), { status: 200 });
  const cmdletOk = () => new Response(JSON.stringify({ value: [{ Name: "org" }] }), { status: 200 });

  beforeEach(() => {
    resetExoTokenStateForTests();
    invalidateExoAppAccessCache({ tenantId: "tenant-app", clientId: "app-1" });
  });
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("classifies the real Phase 0 token shape as read-only Global Reader access", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(tokenFor({ roles: ["Exchange.ManageAsApp"], wids: [GLOBAL_READER] })) as any;
    const r = await getExoAppOnlyAccess(tenant().credentials);
    expect(r.access).toMatchObject({ status: "ok", role: "globalReader", canWrite: false, method: "clientSecret" });
    expect(r.token).toBeTruthy();
  });

  it("runs cmdlets with the app-only token when set up, never touching the sign-in token", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(tokenFor({ roles: ["Exchange.ManageAsApp"], wids: [GLOBAL_READER] })).mockResolvedValueOnce(cmdletOk());
    global.fetch = fetchMock as any;
    const result = await invokeExoCommand(tenant({ exoRefreshToken: "rt-a" }), "Get-OrganizationConfig");
    expect(result.items).toHaveLength(1);
    // Token request used the client secret with the Exchange scope - no refresh_token grant.
    const tokenBody = new URLSearchParams(String((fetchMock.mock.calls[0][1] as RequestInit).body));
    expect(tokenBody.get("grant_type")).toBe("client_credentials");
    expect(tokenBody.get("scope")).toBe("https://outlook.office365.com/.default");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("falls back to the older sign-in when app-only isn't set up", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(tokenFor({ roles: [], wids: [] })) // app token without the permission
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "delegated", refresh_token: "rt-b", expires_in: 1 }), { status: 200 }))
      .mockResolvedValueOnce(cmdletOk());
    global.fetch = fetchMock as any;
    const result = await invokeExoCommand(tenant({ exoRefreshToken: "rt-a" }), "Get-OrganizationConfig");
    expect(result.error).toBeUndefined();
    expect(new URLSearchParams(String((fetchMock.mock.calls[1][1] as RequestInit).body)).get("grant_type")).toBe("refresh_token");
  });

  it("explains what's missing when neither path is available", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(tokenFor({ roles: ["Exchange.ManageAsApp"], wids: [] })) as any;
    const result = await testExoConnectivity(tenant());
    expect(result).toMatchObject({ connected: false, mode: "none" });
    expect(result.appAccess?.status).toBe("notSetUp");
    expect(result.error).toMatch(/Assign Exchange Administrator/);
  });
});
