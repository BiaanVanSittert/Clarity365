import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchAlertPolicyInventory, regionFromRedirect, resetSccCachesForTests } from "./scc-client";

// Only the network boundary (global fetch) is mocked. Responses mirror what
// Microsoft returned live on 2026-10-02.
const fakeJwt = (claims: object) => `x.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.y`;
const tenant = { id: "t1", credentials: { tenantId: "tenant-guid", clientId: "app-1", clientSecret: "secret", authMode: "secret" } } as any;
const GRAPH = { Authorization: "Bearer graph" };

const tokenOk = () => new Response(JSON.stringify({ access_token: fakeJwt({ roles: ["Exchange.ManageAsApp"], wids: ["global-reader"] }), expires_in: 3600 }), { status: 200 });
const orgOk = () => new Response(JSON.stringify({ value: [{ verifiedDomains: [{ name: "contoso.com" }, { name: "contoso.onmicrosoft.com", isInitial: true }] }] }), { status: 200 });
const redirect = (region = "zaf01b") => new Response(null, { status: 302, headers: { location: `https://${region}.admin.protection.outlook.com:446/adminapi/beta/tenant-guid/InvokeCommand` } });
const policies = () => new Response(JSON.stringify({ value: [{ Name: "Audit logging changed", Operation: ["Set-AdminAuditLogConfig"], Disabled: false, NotifyUser: ["a@contoso.com"], NotificationEnabled: true }] }), { status: 200 });

const urlOf = (call: unknown[]) => String(call[0]);
const headersOf = (call: unknown[]) => (call[1] as RequestInit).headers as Record<string, string>;

describe("fetchAlertPolicyInventory", () => {
  const originalFetch = global.fetch;
  beforeEach(() => resetSccCachesForTests());
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("finds the tenant's region, then reads alert policies from the regional host", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(tokenOk()).mockResolvedValueOnce(orgOk()).mockResolvedValueOnce(redirect()).mockResolvedValueOnce(policies());
    global.fetch = fetchMock as any;

    const inventory = await fetchAlertPolicyInventory(tenant, GRAPH);

    expect(inventory.unavailable).toBeUndefined();
    expect(inventory.policies.map((p) => p.name)).toEqual(["Audit logging changed"]);
    // Token for the Security & Compliance resource, using the client secret.
    const tokenBody = new URLSearchParams(String((fetchMock.mock.calls[0][1] as RequestInit).body));
    expect(tokenBody.get("scope")).toBe("https://ps.compliance.protection.outlook.com/.default");
    expect(tokenBody.get("grant_type")).toBe("client_credentials");
    // Region discovery uses the initial onmicrosoft domain, not the tenant id.
    expect(urlOf(fetchMock.mock.calls[2])).toBe("https://ps.compliance.protection.outlook.com/adminapi/beta/tenant-guid/InvokeCommand");
    expect(headersOf(fetchMock.mock.calls[2])["X-AnchorMailbox"]).toBe("UPN:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@contoso.onmicrosoft.com");
    // The read goes to the public regional host, never the :446 backend from the redirect.
    expect(urlOf(fetchMock.mock.calls[3])).toBe("https://zaf01b.ps.compliance.protection.outlook.com/adminapi/beta/tenant-guid/InvokeCommand");
    // Read-only: the only cmdlet ever sent is Get-ProtectionAlert.
    for (const i of [2, 3]) expect(JSON.parse(String((fetchMock.mock.calls[i][1] as RequestInit).body)).CmdletInput.CmdletName).toBe("Get-ProtectionAlert");
  });

  it("reuses the token and region on the next read", async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(tokenOk()).mockResolvedValueOnce(orgOk()).mockResolvedValueOnce(redirect("eur03b")).mockResolvedValueOnce(policies()).mockResolvedValueOnce(policies());
    global.fetch = fetchMock as any;
    await fetchAlertPolicyInventory(tenant, GRAPH);
    await fetchAlertPolicyInventory(tenant, GRAPH);
    expect(fetchMock).toHaveBeenCalledTimes(5);
    expect(urlOf(fetchMock.mock.calls[4])).toContain("eur03b.ps.compliance.protection.outlook.com");
  });

  it("reports 'not set up' when the token carries no Exchange.ManageAsApp role", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({ access_token: fakeJwt({ roles: [] }), expires_in: 3600 }), { status: 200 })) as any;
    const inventory = await fetchAlertPolicyInventory(tenant, GRAPH);
    expect(inventory).toMatchObject({ policies: [], unavailable: "notSetUp" });
    expect(inventory.detail).toMatch(/Exchange\.ManageAsApp/);
  });

  it("reports 'not set up' when Microsoft refuses the read (no role on the app)", async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(tokenOk()).mockResolvedValueOnce(orgOk()).mockResolvedValueOnce(redirect()).mockResolvedValueOnce(new Response("", { status: 401 })) as any;
    expect((await fetchAlertPolicyInventory(tenant, GRAPH)).unavailable).toBe("notSetUp");
  });

  it("reports an error - never an empty list - when the region can't be found", async () => {
    const containerError = () => new Response(JSON.stringify({ error: { message: "Could not find the organization container" } }), { status: 500 });
    global.fetch = vi.fn().mockResolvedValueOnce(tokenOk()).mockResolvedValueOnce(orgOk()).mockResolvedValue(containerError()) as any;
    const inventory = await fetchAlertPolicyInventory(tenant, GRAPH);
    expect(inventory.unavailable).toBe("error");
    expect(inventory.detail).toMatch(/region/);
  });

  it("reports an error and forgets the region when the regional read fails", async () => {
    const boom = () => new Response(JSON.stringify({ error: { message: "Server busy" } }), { status: 500 });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(tokenOk())
      .mockResolvedValueOnce(orgOk())
      .mockResolvedValueOnce(redirect())
      .mockResolvedValueOnce(boom())
      // second attempt looks the region up again
      .mockResolvedValueOnce(orgOk())
      .mockResolvedValueOnce(redirect("eur01b"))
      .mockResolvedValueOnce(policies());
    global.fetch = fetchMock as any;
    const first = await fetchAlertPolicyInventory(tenant, GRAPH);
    expect(first).toMatchObject({ unavailable: "error", detail: "Server busy" });
    const second = await fetchAlertPolicyInventory(tenant, GRAPH);
    expect(second.policies).toHaveLength(1);
  });

  it("never throws when the network is down", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("getaddrinfo ENOTFOUND")) as any;
    expect((await fetchAlertPolicyInventory(tenant, GRAPH)).unavailable).toBe("error");
  });

  it("needs a client secret", async () => {
    const noSecret = { id: "t2", credentials: { tenantId: "x", clientId: "y", authMode: "secret" } } as any;
    expect((await fetchAlertPolicyInventory(noSecret, GRAPH)).unavailable).toBe("notSetUp");
  });
});

describe("regionFromRedirect", () => {
  it("takes the region from the backend host and rejects anything else", () => {
    expect(regionFromRedirect("https://zaf01b.admin.protection.outlook.com:446/adminapi/beta/x/InvokeCommand")).toBe("zaf01b");
    expect(regionFromRedirect("https://EUR03B.admin.protection.outlook.com/x")).toBe("eur03b");
    expect(regionFromRedirect(null)).toBeUndefined();
    expect(regionFromRedirect("not a url")).toBeUndefined();
  });
});
