import { describe, expect, it } from "vitest";
import { buildSignInReport, renderSignInReportHtml, signInReportCsvTables } from "./signin-report";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { SignInEvent, TenantSecuritySnapshot } from "../types";

const NOW = new Date("2026-10-01T12:00:00Z");

let seq = 0;
function signIn(overrides: Partial<SignInEvent> & { at: string; user?: string; country?: string; ip?: string }): SignInEvent {
  const { at, user = "ann@contoso.com", country = "ZA", ip = "203.0.113.10", ...rest } = overrides;
  return {
    id: `s${++seq}`,
    createdDateTime: at,
    userPrincipalName: user,
    userDisplayName: user.split("@")[0],
    userId: user,
    ipAddress: ip,
    location: { city: "", state: "", country },
    clientApp: "Browser",
    appDisplayName: "Office 365",
    status: "success",
    errorCode: 0,
    isRisky: false,
    riskLevel: "none",
    deviceDetail: { operatingSystem: "Windows", browser: "Edge", isCompliant: true, isManaged: true },
    appliedConditionalAccessPolicies: [],
    hasReportOnlyFailure: false,
    reportOnlyFailedPolicies: [],
    ...rest,
  } as SignInEvent;
}

function snapshotWith(signIns: SignInEvent[], extra: Partial<TenantSecuritySnapshot> = {}): TenantSecuritySnapshot {
  return {
    tenant: { displayName: "Contoso", defaultDomainName: "contoso.com" },
    signIns,
    conditionalAccess: {
      policies: [],
      namedLocations: [
        { id: "l1", displayName: "Head office", kind: "ip", ipRanges: ["203.0.113.0/24"], isTrusted: true },
        { id: "l2", displayName: "Allowed countries", kind: "country", countries: ["ZA", "GB"] },
      ],
    },
    ...extra,
  } as unknown as TenantSecuritySnapshot;
}

const MFA = { requirement: "multiFactor" as const, methods: ["Password", "Mobile app notification"], fromExistingSession: false };
const NO_MFA = { requirement: "singleFactor" as const, methods: ["Password"], fromExistingSession: false };

describe("buildSignInReport", () => {
  const events = [
    signIn({ at: "2026-09-20T08:00:00Z", authentication: MFA }),
    signIn({ at: "2026-09-21T08:00:00Z", authentication: MFA }),
    signIn({ at: "2026-09-22T08:00:00Z", user: "bob@contoso.com", authentication: NO_MFA, ip: "198.51.100.5" }),
    signIn({ at: "2026-09-23T08:00:00Z", user: "bob@contoso.com", status: "failed", errorCode: 50126, ip: "198.51.100.5" }),
    signIn({ at: "2026-09-24T08:00:00Z", user: "bob@contoso.com", status: "ca_blocked", errorCode: 53003, country: "RU", ip: "192.0.2.77" }),
    signIn({ at: "2026-09-30T09:00:00Z", user: "cat@partner.com", userType: "guest", country: "GB", ip: "192.0.2.9", clientApp: "IMAP4", authentication: NO_MFA }),
  ];
  const report = buildSignInReport(snapshotWith(events), { now: NOW });

  it("counts the headline numbers", () => {
    expect(report.summary).toMatchObject({
      total: 6,
      succeeded: 4,
      failed: 1,
      blocked: 1,
      users: 3,
      guests: 1,
      countries: 3,
      ipAddresses: 4,
      outsideHome: 2,
      legacy: 1,
      mfaRequired: 2,
      withoutMfa: 2,
    });
    expect(report.homeCountry).toBe("ZA");
    expect(report.from).toBe("2026-09-20T08:00:00Z");
    expect(report.to).toBe("2026-09-30T09:00:00Z");
  });

  it("breaks sign-ins down by country, marking home and named locations", () => {
    expect(report.byCountry.map((c) => [c.code, c.signIns, c.isHome])).toEqual([
      ["ZA", 4, true],
      ["GB", 1, false],
      ["RU", 1, false],
    ]);
    expect(report.byCountry[0].namedLocations).toEqual(["Allowed countries"]);
    expect(report.byCountry[2]).toMatchObject({ blocked: 1, succeeded: 0, namedLocations: [] });
  });

  it("matches IP addresses to the tenant's named locations", () => {
    const office = report.byIp.find((i) => i.ipAddress === "203.0.113.10");
    expect(office).toMatchObject({ signIns: 2, namedLocation: "Head office", trusted: true });
    expect(report.byIp.find((i) => i.ipAddress === "198.51.100.5")).toMatchObject({ namedLocation: undefined, trusted: false, users: 1, succeeded: 1, failed: 1 });
  });

  it("summarises each user, including how they authenticated", () => {
    const bob = report.byUser.find((u) => u.userPrincipalName === "bob@contoso.com")!;
    expect(bob).toMatchObject({ signIns: 3, succeeded: 1, failed: 1, blocked: 1, countries: ["ZA", "RU"], ipAddresses: 2, withoutMfa: 1, lastSignIn: "2026-09-24T08:00:00Z" });
    expect(bob.authentication).toContain("No MFA required: Password");
    expect(report.byUser.find((u) => u.userPrincipalName === "ann@contoso.com")!.authentication).toEqual(["MFA: Mobile app notification"]);
    expect(report.byAuthentication[0]).toMatchObject({ signIns: 2 });
  });

  it("flags legacy clients, sign-ins abroad and sign-ins without MFA", () => {
    expect(report.byClient.find((c) => c.label === "IMAP4")?.legacy).toBe(true);
    const ids = report.findings.map((f) => f.id);
    expect(ids).toEqual(["legacy", "outsideHome", "newCountry", "withoutMfa"].filter((id) => ids.includes(id as any)));
    expect(report.findings.find((f) => f.id === "legacy")).toMatchObject({ severity: "red", total: 1 });
    // The Russian sign-in was blocked, so only the UK one counts as a successful sign-in abroad.
    expect(report.findings.find((f) => f.id === "outsideHome")?.total).toBe(1);
    expect(report.findings.find((f) => f.id === "withoutMfa")?.total).toBe(2);
  });

  it("filters by period and by user", () => {
    const lastWeek = buildSignInReport(snapshotWith(events), { now: NOW, days: 7 });
    expect(lastWeek.summary.total).toBe(1);
    expect(lastWeek.requestedDays).toBe(7);
    const bobOnly = buildSignInReport(snapshotWith(events), { now: NOW, user: "BOB" });
    expect(bobOnly.summary).toMatchObject({ total: 3, users: 1 });
    // Home country still comes from the whole tenant, not the filtered user.
    expect(bobOnly.homeCountry).toBe("ZA");
  });
});

describe("worth a look: patterns over time", () => {
  it("flags one user succeeding from two countries within two hours, but not days apart", () => {
    const report = buildSignInReport(
      snapshotWith([
        signIn({ at: "2026-09-10T08:00:00Z" }),
        signIn({ at: "2026-09-25T08:00:00Z" }),
        signIn({ at: "2026-09-25T08:40:00Z", country: "NG", ip: "192.0.2.1" }),
        signIn({ at: "2026-09-12T08:00:00Z", user: "dan@contoso.com" }),
        signIn({ at: "2026-09-20T08:00:00Z", user: "dan@contoso.com", country: "GB", ip: "192.0.2.2" }),
      ]),
      { now: NOW }
    );
    const two = report.findings.find((f) => f.id === "twoCountries")!;
    expect(two.total).toBe(1);
    expect(two.rows[0]).toMatchObject({ user: "ann@contoso.com", what: "South Africa then Nigeria within 40 minutes" });
  });

  it("flags a first sign-in from a new country only when it is recent and the user has history elsewhere", () => {
    const report = buildSignInReport(
      snapshotWith([
        signIn({ at: "2026-09-01T08:00:00Z" }),
        signIn({ at: "2026-09-29T08:00:00Z", country: "FR", ip: "192.0.2.3" }),
        // Old trip: not new any more.
        signIn({ at: "2026-09-02T08:00:00Z", user: "dan@contoso.com" }),
        signIn({ at: "2026-09-05T08:00:00Z", user: "dan@contoso.com", country: "GB", ip: "192.0.2.2" }),
        // Only ever seen abroad: nothing to compare with.
        signIn({ at: "2026-09-30T08:00:00Z", user: "eve@contoso.com", country: "US", ip: "192.0.2.4" }),
      ]),
      { now: NOW }
    );
    const fresh = report.findings.find((f) => f.id === "newCountry")!;
    expect(fresh.rows.map((r) => [r.user, r.what])).toEqual([["ann@contoso.com", "First sign-in from France"]]);
  });

  it("flags a burst of failures followed by a success, once", () => {
    const failures = [0, 2, 4, 6, 8].map((m) => signIn({ at: `2026-09-25T08:0${m}:00Z`, status: "failed", errorCode: 50126, ip: "192.0.2.50" }));
    const report = buildSignInReport(snapshotWith([...failures, signIn({ at: "2026-09-25T08:10:00Z", ip: "192.0.2.50" }), signIn({ at: "2026-09-25T08:12:00Z", ip: "192.0.2.50" })]), { now: NOW });
    const burst = report.findings.find((f) => f.id === "failuresThenSuccess")!;
    expect(burst.total).toBe(1);
    expect(burst.severity).toBe("red");

    const fewer = buildSignInReport(snapshotWith([...failures.slice(0, 4), signIn({ at: "2026-09-25T08:10:00Z" })]), { now: NOW });
    expect(fewer.findings.find((f) => f.id === "failuresThenSuccess")).toBeUndefined();
  });
});

describe("honesty about what the data covers", () => {
  it("says MFA details are unavailable instead of reporting zero", () => {
    const report = buildSignInReport(snapshotWith([signIn({ at: "2026-09-25T08:00:00Z" })]), { now: NOW });
    expect(report.authDetailsAvailable).toBe(false);
    expect(report.byAuthentication).toEqual([]);
    expect(report.findings.find((f) => f.id === "withoutMfa")).toBeUndefined();
    expect(renderSignInReportHtml(report)).toContain("The MFA method is not available");
    expect(signInReportCsvTables(report).map((t) => t.name)).not.toContain("Authentication");
  });

  it("warns when the requested period reaches further back than the synced sign-ins", () => {
    const snapshot = snapshotWith([signIn({ at: "2026-09-29T08:00:00Z" })], {
      signInCoverage: { windowDays: 30, count: 1, complete: false, incompleteReason: "limit", from: "2026-09-29T08:00:00Z", to: "2026-09-29T08:00:00Z" },
    });
    expect(buildSignInReport(snapshot, { now: NOW, days: 30 }).periodWarning).toMatch(/only loaded back to 2026-09-29/);
    expect(buildSignInReport(snapshot, { now: NOW, days: 1 }).periodWarning).toBeUndefined();
  });

  it("handles a tenant with no sign-ins", () => {
    const report = buildSignInReport(snapshotWith([]), { now: NOW });
    expect(report.summary.total).toBe(0);
    expect(report.findings).toEqual([]);
    expect(renderSignInReportHtml(report)).toContain("No sign-ins in this period");
  });
});

describe("output", () => {
  const hostile = signIn({ at: "2026-09-25T08:00:00Z", user: "<script>alert(1)</script>@x.com", appDisplayName: `=cmd|' /C calc'!A0 <img src=x onerror=alert(1)>`, clientApp: "IMAP4" });
  const report = buildSignInReport(snapshotWith([hostile, signIn({ at: "2026-09-26T08:00:00Z", authentication: MFA })]), { now: NOW });

  it("escapes tenant-supplied text in the printable report", () => {
    const html = renderSignInReportHtml(report);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;@x.com");
    expect(html).toContain("Contoso");
  });

  it("produces one CSV table per section with matching column counts", () => {
    const tables = signInReportCsvTables(report);
    expect(tables.map((t) => t.name)).toEqual(["Users", "Countries", "IPAddresses", "Authentication", "Apps", "Clients", "Devices", "WorthALook"]);
    for (const t of tables) for (const r of t.rows) expect(r.length).toBe(t.headers.length);
    expect(tables[0].rows).toHaveLength(2);
  });

  it("limits long tables in the printable report and says so", () => {
    const many = Array.from({ length: 25 }, (_, i) => signIn({ at: "2026-09-25T08:00:00Z", user: `user${i}@contoso.com`, ip: `192.0.2.${i}` }));
    const html = renderSignInReportHtml(buildSignInReport(snapshotWith(many), { now: NOW }));
    expect(html).toContain("Showing the top 10 of 25");
  });
});

describe("demo tenants", () => {
  it("builds a report for every demo tenant without throwing", () => {
    for (const snapshot of Object.values(MOCK_TENANT_DATA)) {
      const report = buildSignInReport(snapshot as TenantSecuritySnapshot, { now: NOW });
      expect(report.summary.total).toBe((snapshot as TenantSecuritySnapshot).signIns.length);
      expect(renderSignInReportHtml(report)).toContain("Sign-in report");
    }
  });
});
