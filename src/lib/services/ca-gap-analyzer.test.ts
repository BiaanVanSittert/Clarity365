import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { CAPolicyRule, TenantSecuritySnapshot } from "../types";
import { analyzeCaGaps, CaGapCell } from "./ca-gap-analyzer";

const NOW = new Date("2026-09-30T00:00:00Z");
const GA_ROLE = "62e90394-69f5-4237-9190-012177145e10";

function policy(id: string, overrides: Partial<Omit<CAPolicyRule, "conditions">> & { conditions?: Partial<CAPolicyRule["conditions"]> } = {}): CAPolicyRule {
  const { conditions, ...rest } = overrides;
  return {
    id,
    name: id,
    baselineCode: null,
    state: "enabled",
    modifiedDateTime: "2026-09-01T00:00:00Z",
    createdDateTime: "2026-01-01T00:00:00Z",
    grantControls: ["mfa"],
    matchesBaseline: false,
    ...rest,
    conditions: {
      users: { include: ["All"], exclude: ["upn:breakglass@x.com"], includeGroupIds: [] },
      applications: { include: ["All"], exclude: [] },
      clientAppTypes: ["all"],
      ...conditions,
    },
  };
}

// A live-looking tenant (isDemo false) whose policies all carry Stage 1 fields.
function tenantWith(policies: CAPolicyRule[], extra: Partial<TenantSecuritySnapshot> = {}): TenantSecuritySnapshot {
  const base = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  return {
    ...base,
    tenant: { ...base.tenant, isDemo: false },
    conditionalAccess: { ...base.conditionalAccess, policies, namedLocations: [] },
    mfaAudit: [],
    accountClassification: { ...base.accountClassification, users: [] },
    groups: [],
    identitySettings: { securityDefaultsEnabled: false },
    ...extra,
  };
}

const cell = (cells: CaGapCell[], persona: string, control: string) => cells.find((c) => c.persona === persona && c.control === control)!;

describe("matrix cells", () => {
  it("MFA for all users covers admins, users and guests; a report-only policy shows as report-only", () => {
    const a = analyzeCaGaps(tenantWith([policy("mfa-all"), policy("ca10", { state: "enabledForReportingButNotEnforced", grantControls: ["authenticationStrength:Phishing-resistant MFA"], conditions: { users: { include: [], exclude: [], includeRoles: [GA_ROLE], includeGroupIds: [] } } })]), NOW);
    expect(cell(a.matrix, "admins", "mfa").state).toBe("enforced");
    expect(cell(a.matrix, "users", "mfa").state).toBe("enforced");
    expect(cell(a.matrix, "guests", "mfa").state).toBe("enforced");
    expect(cell(a.matrix, "admins", "phishingResistant")).toMatchObject({ state: "reportOnly", policies: [{ id: "ca10" }] });
    // Optional for non-admins, so not scored as a gap...
    expect(cell(a.matrix, "users", "phishingResistant").state).toBe("notApplicable");
    // ...but still shown when a policy does enforce it.
    const enforcedForAll = analyzeCaGaps(tenantWith([policy("pr-all", { grantControls: ["authenticationStrength:Phishing-resistant MFA"] })]), NOW);
    expect(cell(enforcedForAll.matrix, "users", "phishingResistant").state).toBe("enforced");
  });

  it("marks guest device and risk cells not applicable, and workload identities unlicensed without a policy", () => {
    const a = analyzeCaGaps(tenantWith([]), NOW);
    expect(cell(a.matrix, "guests", "managedDevice").state).toBe("notApplicable");
    expect(cell(a.matrix, "guests", "signInRisk").state).toBe("notApplicable");
    expect(cell(a.matrix, "workloadIdentities", "signInRisk").state).toBe("unlicensed");
    expect(cell(a.matrix, "workloadIdentities", "mfa").state).toBe("notApplicable");
  });

  it("legacy authentication counts only when both Exchange ActiveSync and other clients are blocked", () => {
    const easOnly = analyzeCaGaps(tenantWith([policy("eas", { grantControls: ["block"], conditions: { clientAppTypes: ["exchangeActiveSync"] } })]), NOW);
    expect(cell(easOnly.matrix, "users", "legacyBlocked")).toMatchObject({ state: "noPolicy" });
    expect(cell(easOnly.matrix, "users", "legacyBlocked").note).toMatch(/Only part/);
    const both = analyzeCaGaps(tenantWith([policy("legacy", { grantControls: ["block"], conditions: { clientAppTypes: ["exchangeActiveSync", "other"] } })]), NOW);
    expect(cell(both.matrix, "users", "legacyBlocked").state).toBe("enforced");
  });

  it("risk cells are unlicensed without Entra ID P2", () => {
    const base = tenantWith([policy("risk", { conditions: { signInRiskLevels: ["high"] } })]);
    const noP2 = { ...base, capabilities: [], tenant: { ...base.tenant, tier: "M365_BP" as any } };
    expect(cell(analyzeCaGaps(noP2, NOW).matrix, "users", "signInRisk").state).toBe("unlicensed");
  });

  it("security defaults provide MFA and the legacy block when no CA policy is enabled", () => {
    const a = analyzeCaGaps(tenantWith([], { identitySettings: { securityDefaultsEnabled: true } }), NOW);
    expect(cell(a.matrix, "admins", "mfa").state).toBe("enforced");
    expect(cell(a.matrix, "users", "legacyBlocked").state).toBe("enforced");
    expect(a.findings.map((f) => f.id)).toContain("securitydefaults");
  });

  it("a location block counts as a location restriction", () => {
    const a = analyzeCaGaps(
      tenantWith([policy("geo", { grantControls: ["block"], conditions: { locations: { include: ["All"], exclude: ["loc-za"] } } })], {
        conditionalAccess: {
          ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].conditionalAccess,
          policies: [policy("geo", { grantControls: ["block"], conditions: { locations: { include: ["All"], exclude: ["loc-za"] } } })],
          namedLocations: [{ id: "loc-za", displayName: "ZA", kind: "country", countries: ["ZA"] }],
        },
      }),
      NOW,
      "ZA"
    );
    expect(cell(a.matrix, "users", "locationRestrictions").state).toBe("enforced");
  });
});

describe("score", () => {
  it("is 0 with no policies and near 10 for the zero-trust demo tenant", () => {
    expect(analyzeCaGaps(tenantWith([]), NOW).score).toBe(0);
    const woodgrove = analyzeCaGaps(MOCK_TENANT_DATA["tenant-woodgrove-fsi"], NOW);
    expect(woodgrove.score).toBeGreaterThanOrEqual(8);
    expect(woodgrove.enforcedControls).toBeLessThanOrEqual(woodgrove.scoredControls);
  });

  it("weaker demo tenants score lower than Woodgrove", () => {
    const wg = analyzeCaGaps(MOCK_TENANT_DATA["tenant-woodgrove-fsi"], NOW).score;
    expect(analyzeCaGaps(MOCK_TENANT_DATA["tenant-fabrikam-logistics"], NOW).score).toBeLessThan(wg);
    expect(analyzeCaGaps(MOCK_TENANT_DATA["tenant-northwind-health"], NOW).score).toBeLessThan(wg);
  });
});

describe("findings", () => {
  it("flags an enforced block for everyone with no exclusions as a critical lockout risk", () => {
    const a = analyzeCaGaps(tenantWith([policy("block-all", { grantControls: ["block"], conditions: { users: { include: ["All"], exclude: [], includeGroupIds: [] } } })]), NOW);
    expect(a.findings[0]).toMatchObject({ id: "lockout", severity: "critical" });
  });

  it("does not flag lockout when an account is excluded", () => {
    const a = analyzeCaGaps(tenantWith([policy("mfa-all")]), NOW);
    expect(a.findings.map((f) => f.id)).not.toContain("lockout");
  });

  it("raises the external-provider precaution for risk remediation with an authentication strength", () => {
    const a = analyzeCaGaps(
      tenantWith([policy("ca07", { grantControls: ["riskRemediation", "authenticationStrength:Multifactor authentication"], grantOperator: "AND", conditions: { userRiskLevels: ["high"] } })]),
      NOW
    );
    expect(a.findings.find((f) => f.id === "guidance:external-provider")).toMatchObject({ severity: "high", source: "Microsoft guidance", policies: ["ca07"] });
  });

  it("flags device registration when a location block exists but no registration policy", () => {
    const a = analyzeCaGaps(tenantWith([policy("geo", { grantControls: ["block"], conditions: { locations: { include: ["All"], exclude: ["AllTrusted"] } } })]), NOW);
    expect(a.findings.find((f) => f.id === "registration:device")?.policies).toEqual(["geo"]);
  });

  it("reports stale report-only policies and missing critical coverage, most severe first", () => {
    const a = analyzeCaGaps(tenantWith([policy("old", { state: "enabledForReportingButNotEnforced", modifiedDateTime: "2026-06-01T00:00:00Z" })]), NOW);
    const ids = a.findings.map((f) => f.id);
    expect(ids).toContain("hygiene:report-only-old");
    expect(ids).toContain("reportonly:admins:mfa");
    const order = ["critical", "high", "medium", "low"];
    expect(a.findings.map((f) => order.indexOf(f.severity))).toEqual([...a.findings.map((f) => order.indexOf(f.severity))].sort((x, y) => x - y));
  });

  it("flags pre-simulation policies as needing a re-sync", () => {
    const stale = policy("old-shape");
    delete (stale.conditions.users as any).includeGroupIds;
    expect(analyzeCaGaps(tenantWith([stale]), NOW).needsResync).toBe(true);
  });
});
