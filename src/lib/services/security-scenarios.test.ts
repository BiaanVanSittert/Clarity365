import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { SCENARIO_DEFINITIONS, SCENARIO_SECTIONS, evaluateScenarios, rollUpVerdict } from "./security-scenarios";

const NOW = new Date("2026-09-30T12:00:00Z");
const run = (tenantId: string) => evaluateScenarios(MOCK_TENANT_DATA[tenantId], { now: NOW });
const find = (results: ReturnType<typeof evaluateScenarios>, id: string) => results.find((r) => r.id === id)!;
const check = (results: ReturnType<typeof evaluateScenarios>, scenarioId: string, checkId: string) => find(results, scenarioId).checks.find((c) => c.id === checkId)!;

describe("scenario catalog", () => {
  it("has the 17 requested scenarios across the four sections", () => {
    expect(SCENARIO_DEFINITIONS).toHaveLength(17);
    const bySection = Object.fromEntries(SCENARIO_SECTIONS.map((s) => [s.id, SCENARIO_DEFINITIONS.filter((d) => d.section === s.id).length]));
    expect(bySection).toEqual({ identity: 9, audit: 3, exchange: 2, sharepoint: 3 });
    expect(new Set(SCENARIO_DEFINITIONS.map((d) => d.id)).size).toBe(17);
  });
});

describe("rollUpVerdict", () => {
  it("is red when any layer lets the attack through, green only when every check holds", () => {
    expect(rollUpVerdict([{ status: "prevented" }, { status: "notPrevented" }])).toBe("notPrevented");
    expect(rollUpVerdict([{ status: "prevented" }, { status: "prevented" }])).toBe("prevented");
    expect(rollUpVerdict([{ status: "prevented" }, { status: "partial" }])).toBe("partial");
    expect(rollUpVerdict([{ status: "prevented" }, { status: "notAssessed" }])).toBe("partial");
    expect(rollUpVerdict([{ status: "notAssessed" }])).toBe("notAssessed");
  });
});

describe("Woodgrove (strict)", () => {
  const r = run("tenant-woodgrove-fsi");

  it("prevents the core identity attacks", () => {
    for (const id of ["token-replay", "password-spray", "legacy-mailbox", "device-code", "oauth-consent", "bulk-sync", "guest-reshare"]) {
      expect({ id, verdict: find(r, id).verdict }).toEqual({ id, verdict: "prevented" });
    }
  });

  it("still flags device registration from abroad (no registration policy)", () => {
    expect(check(r, "foreign-country", "device-registration").status).toBe("notPrevented");
    expect(find(r, "foreign-country").verdict).toBe("notPrevented");
  });

  it("marks manual checks as not assessed, never green", () => {
    expect(check(r, "silent-tenant", "alerting").status).toBe("notAssessed");
    expect(find(r, "silent-tenant").verdict).toBe("partial");
  });
});

describe("Northwind (the silent tenant)", () => {
  const r = run("tenant-northwind-health");

  it("flags auditing off, standing admins and risky consent", () => {
    expect(check(r, "silent-tenant", "ual").status).toBe("notPrevented");
    expect(check(r, "role-escalation", "ga-count").status).toBe("notPrevented");
    expect(check(r, "role-escalation", "standing-access").detail).toMatch(/Entra ID P2/);
    const risky = check(r, "oauth-consent", "risky-grants");
    expect(risky.status).toBe("notPrevented");
    expect(risky.items?.[0]).toMatch(/Mail Backup Pro/);
  });

  it("counts gaps per scenario", () => {
    const s = find(r, "guest-reshare");
    expect(s.gaps).toBe(s.counts.partial + s.counts.notPrevented);
    expect(s.gaps).toBeGreaterThan(0);
  });
});

describe("Fabrikam (Exchange never connected)", () => {
  const r = run("tenant-fabrikam-logistics");

  it("reports Exchange checks as not assessed rather than guessing", () => {
    expect(check(r, "legacy-mailbox", "smtp-auth-org").status).toBe("notAssessed");
    expect(check(r, "legacy-mailbox", "smtp-auth-org").detail).toMatch(/Exchange Online isn't connected/);
    expect(check(r, "oauth-consent", "risky-grants").status).toBe("notAssessed");
  });
});

describe("Anyone links", () => {
  it("always carries the sensitivity-label warning (user decision)", () => {
    expect(find(run("tenant-contoso-corp"), "anyone-link").warning).toMatch(/Sensitivity labels aren't synced/);
  });

  it("reports link defaults as not assessed when Graph doesn't report them", () => {
    const snap = MOCK_TENANT_DATA["tenant-fabrikam-logistics"];
    const anyone = { ...snap, sharePoint: { ...snap.sharePoint, tenantSharingLevel: "Anyone" as const, linkDefaultsReported: false } };
    const c = evaluateScenarios(anyone, { now: NOW }).find((x) => x.id === "anyone-link")!.checks.find((x) => x.id === "expiry")!;
    expect(c.status).toBe("notAssessed");
  });
});

describe("OAuth consent grants unavailable", () => {
  it("names the permission to grant when grants couldn't be read", () => {
    const snap = MOCK_TENANT_DATA["tenant-contoso-corp"];
    const noPerm = { ...snap, oauthConsentGrants: { grants: [], truncated: false, unavailable: "missingPermission" as const } };
    const c = evaluateScenarios(noPerm, { now: NOW }).find((x) => x.id === "oauth-consent")!.checks.find((x) => x.id === "risky-grants")!;
    expect(c.status).toBe("notAssessed");
    expect(c.fix).toMatch(/DelegatedPermissionGrant\.Read\.All/);
  });
});
