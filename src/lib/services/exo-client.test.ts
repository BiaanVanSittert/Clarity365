import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getExoAccessToken, resetExoTokenStateForTests, resolveLatestExoRefreshToken } from "./exo-client";
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
