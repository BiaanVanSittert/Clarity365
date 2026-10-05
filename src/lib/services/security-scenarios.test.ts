import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { SCENARIO_DEFINITIONS, SCENARIO_SECTIONS, applyManualConfirmation, evaluateScenarios, rollUpVerdict } from "./security-scenarios";
import { TenantSecuritySnapshot } from "../types";

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

  it("answers the alert checks from the tenant's alert policies", () => {
    const audit = check(r, "silent-tenant", "alerting");
    expect(audit.status).toBe("prevented");
    expect(audit.detail).toBe('Alert policy "Audit logging changed" emails 1 recipient(s) when the audit log configuration is changed (Set-AdminAuditLogConfig).');
    // Nothing to confirm by hand when Clarity365 can see it.
    expect(audit.confirmKey).toBeUndefined();
    expect(check(r, "mass-deletion", "alerting").detail).toMatch(/"Bulk user deletion".*\(more than 5 in 60 minutes\)/);
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

describe("alert policy checks", () => {
  it("is red when policies were read and none watches the activity", () => {
    const c = check(run("tenant-northwind-health"), "silent-tenant", "alerting");
    expect(c.status).toBe("notPrevented");
    expect(c.detail).toMatch(/^None of this tenant's 3 Microsoft 365 alert policies fires when/);
    // The command lives in the How to fix guide.
    expect(c.guideId).toBe("alert-audit-config-changes");
    // It may be covered in a tool Clarity365 can't see, so it can be confirmed.
    expect(c.confirmKey).toBe("alert-audit-config");
  });

  it("is orange when an alert is raised but nobody is emailed, and red when it is switched off", () => {
    const r = run("tenant-contoso-corp");
    expect(check(r, "silent-tenant", "alerting")).toMatchObject({ status: "partial", fix: "Add an email recipient to the alert policy." });
    expect(check(r, "mass-deletion", "alerting").status).toBe("notPrevented");
    expect(check(r, "mass-deletion", "alerting").detail).toMatch(/turned off/);
  });

  it("is not assessed - never red - when alert policies couldn't be read", () => {
    const fabrikam = check(run("tenant-fabrikam-logistics"), "silent-tenant", "alerting");
    expect(fabrikam.status).toBe("notAssessed");
    expect(fabrikam.detail).toMatch(/until Exchange app access is set up/);
    expect(fabrikam.confirmKey).toBe("alert-audit-config");

    const snap = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
    const neverSynced = evaluateScenarios({ ...snap, alertPolicies: undefined }, { now: NOW });
    expect(check(neverSynced, "silent-tenant", "alerting").detail).toMatch(/haven't been synced yet/);
    const failed = evaluateScenarios({ ...snap, alertPolicies: { policies: [], unavailable: "error", detail: "Server busy", checkedAt: "" } }, { now: NOW });
    expect(check(failed, "silent-tenant", "alerting")).toMatchObject({ status: "notAssessed", detail: "Alert policies couldn't be read: Server busy." });
  });
});

describe("confirm once", () => {
  const withConfirmation = (tenantId: string, confirmations: TenantSecuritySnapshot["tenant"]["scenarioConfirmations"]) => {
    const snap = MOCK_TENANT_DATA[tenantId];
    return evaluateScenarios({ ...snap, tenant: { ...snap.tenant, scenarioConfirmations: confirmations } }, { now: NOW });
  };

  it("turns a check Clarity365 can't see green once it has been confirmed, and says until when", () => {
    const r = withConfirmation("tenant-northwind-health", { "alert-audit-config": { status: "inPlace", confirmedAt: "2026-09-01T08:00:00Z", note: "Sentinel rule AUD-01" } });
    const c = check(r, "silent-tenant", "alerting");
    expect(c.status).toBe("prevented");
    expect(c.detail).toBe("Confirmed manually on 2026-09-01 (valid until 2027-09-01). Note: Sentinel rule AUD-01");
    expect(c.command).toBeUndefined();
    expect(c.confirmation).toMatchObject({ status: "inPlace", expired: false });
    // The other confirmable check is untouched.
    expect(check(r, "mass-deletion", "alerting").status).toBe("notPrevented");
  });

  it("stops counting after twelve months and asks for a fresh check", () => {
    const r = withConfirmation("tenant-northwind-health", { "alert-audit-config": { status: "inPlace", confirmedAt: "2025-09-29T08:00:00Z" } });
    const c = check(r, "silent-tenant", "alerting");
    expect(c.status).toBe("notPrevented");
    expect(c.detail).toMatch(/Your confirmation from 2025-09-29 is more than 365 days old and no longer counts/);
    expect(c.confirmation?.expired).toBe(true);
  });

  it("turns red when marked as not in place", () => {
    const r = withConfirmation("tenant-fabrikam-logistics", { "alert-audit-config": { status: "notInPlace", confirmedAt: "2026-09-01T08:00:00Z" } });
    expect(check(r, "silent-tenant", "alerting")).toMatchObject({ status: "notPrevented", detail: "Marked as not in place on 2026-09-01." });
  });

  it("never overrides what Clarity365 can read for itself", () => {
    // Contoso's audit alert emails nobody: a confirmation can't paper over that.
    const r = withConfirmation("tenant-contoso-corp", { "alert-audit-config": { status: "inPlace", confirmedAt: "2026-09-01T08:00:00Z" } });
    expect(check(r, "silent-tenant", "alerting").status).toBe("partial");
    const untouched = { id: "x", label: "L", status: "notPrevented" as const, detail: "d" };
    expect(applyManualConfirmation(untouched, { "alert-audit-config": { status: "inPlace", confirmedAt: "2026-09-01T08:00:00Z" } }, NOW)).toBe(untouched);
  });

  it("covers the SharePoint link settings Microsoft doesn't report", () => {
    const snap = MOCK_TENANT_DATA["tenant-fabrikam-logistics"];
    const anyone = { ...snap, sharePoint: { ...snap.sharePoint, tenantSharingLevel: "Anyone" as const, linkDefaultsReported: false } };
    const before = evaluateScenarios(anyone, { now: NOW }).find((x) => x.id === "anyone-link")!;
    expect(before.checks.find((x) => x.id === "expiry")!.confirmKey).toBe("sharepoint-anyone-link-expiry");
    expect(before.checks.find((x) => x.id === "default-link")!.confirmKey).toBe("sharepoint-default-link");

    const confirmed = { ...anyone, tenant: { ...anyone.tenant, scenarioConfirmations: { "sharepoint-anyone-link-expiry": { status: "inPlace" as const, confirmedAt: "2026-09-20T08:00:00Z" } } } };
    const after = evaluateScenarios(confirmed, { now: NOW }).find((x) => x.id === "anyone-link")!;
    expect(after.checks.find((x) => x.id === "expiry")!.status).toBe("prevented");
    expect(after.checks.find((x) => x.id === "default-link")!.status).toBe("notAssessed");
  });
});
