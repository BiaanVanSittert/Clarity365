import { describe, expect, it } from "vitest";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { TenantSecuritySnapshot } from "../types";
import { buildCaEnvironment, buildSimUser, buildSyntheticSimUser, detectLikelyBreakGlassAccounts, listSimAccounts } from "./ca-sim-context";
import { GLOBAL_ADMIN_TEMPLATE_ID } from "../utils/directory-role-templates";
import { SignInContext, evaluateSignIn } from "./ca-policy-evaluator";

function snapshotWith(partial: Partial<TenantSecuritySnapshot>): TenantSecuritySnapshot {
  const base = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  return { ...base, ...partial };
}

const mfaProfile = (id: string, upn: string, extra: Record<string, unknown> = {}) =>
  ({
    id,
    userPrincipalName: upn,
    displayName: upn.split("@")[0],
    jobTitle: "",
    department: "",
    accountEnabled: true,
    isAdmin: false,
    mfaRegistered: true,
    mfaEnforcedByPolicy: true,
    defaultMethod: "ms_authenticator_push",
    registeredMethods: ["ms_authenticator_push"],
    isWeakAuth: false,
    passwordLastSetDateTime: "",
    lastSignInDateTime: "",
    ...extra,
  }) as any;

describe("listSimAccounts", () => {
  it("uses role template ids when present and ignores the placeholder GA name for inferred data", () => {
    const snap = snapshotWith({
      mfaAudit: [
        mfaProfile("u1", "ga@x.com", { isAdmin: true, adminRoles: ["Global Administrator"], adminRoleTemplateIds: [GLOBAL_ADMIN_TEMPLATE_ID] }),
        mfaProfile("u2", "helpdesk@x.com", { isAdmin: true, adminRoles: ["Helpdesk Administrator"], adminRoleTemplateIds: ["729827e3-9c14-49f7-bb1b-9608f156bbb8"] }),
        mfaProfile("u3", "old@x.com", { isAdmin: true, adminRoles: ["Global Administrator"] }),
        mfaProfile("u4", "user@x.com"),
        mfaProfile("u5", "vendor_y.com#EXT#@x.onmicrosoft.com"),
      ],
      accountClassification: { ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].accountClassification, users: [] },
    });
    const lists = listSimAccounts(snap);
    expect(lists.globalAdmins.map((a) => [a.userPrincipalName, a.roleSource])).toEqual([
      ["ga@x.com", "directoryRoles"],
      ["old@x.com", "inferred"],
    ]);
    expect(lists.otherAdmins.map((a) => a.userPrincipalName)).toEqual(["helpdesk@x.com"]);
    expect(lists.standardUsers.map((a) => a.userPrincipalName)).toEqual(["user@x.com"]);
    expect(lists.guests.map((a) => a.userPrincipalName)).toEqual(["vendor_y.com#EXT#@x.onmicrosoft.com"]);
  });

  it("flags accounts that look like break-glass accounts", () => {
    const woodgrove = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
    const snap = snapshotWith({
      mfaAudit: [mfaProfile("bg", "emergency-wg-breakglass@woodgrovefinancial.com", { isAdmin: true, adminRoles: ["Global Administrator"], adminRoleTemplateIds: [GLOBAL_ADMIN_TEMPLATE_ID] })],
      accountClassification: { ...woodgrove.accountClassification, users: [] },
    });
    expect(listSimAccounts(snap).globalAdmins[0].breakGlassReasons?.length).toBeGreaterThan(0);
  });
});

describe("buildCaEnvironment", () => {
  it("marks live policies without Stage 1 fields as incomplete, but never demo policies", () => {
    const live = snapshotWith({ tenant: { ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].tenant, isDemo: false } });
    const incomplete = buildCaEnvironment(live).incompletePolicyIds!;
    // Woodgrove's baseline policies don't set includeGroupIds; its extra policies don't either.
    expect(incomplete.length).toBe(live.conditionalAccess.policies.length);
    expect(buildCaEnvironment(MOCK_TENANT_DATA["tenant-woodgrove-fsi"]).incompletePolicyIds).toEqual([]);
  });
});

describe("buildSimUser", () => {
  it("resolves direct group membership by UPN and marks unknown role names as incomplete", () => {
    const snap = snapshotWith({
      mfaAudit: [mfaProfile("u1", "Sam@X.com", { isAdmin: true, adminRoles: ["Some Custom Role"] })],
      groups: [{ id: "g1", displayName: "Finance", members: ["sam@x.com"] } as any, { id: "g2", displayName: "Other", members: [] } as any],
    });
    const user = buildSimUser(snap, "u1")!;
    expect(user.groupIds).toEqual(["g1"]);
    expect(user.roleTemplateIdsComplete).toBe(false);
  });

  it("returns undefined for an unknown user", () => {
    expect(buildSimUser(snapshotWith({}), "nope")).toBeUndefined();
  });
});

describe("detectLikelyBreakGlassAccounts", () => {
  it("flags Woodgrove's emergency account (named like one and excluded almost everywhere)", () => {
    const found = detectLikelyBreakGlassAccounts(MOCK_TENANT_DATA["tenant-woodgrove-fsi"]);
    expect(found[0].ref).toBe("upn:emergency-wg-breakglass@woodgrovefinancial.com");
    expect(found[0].reasons.length).toBe(2);
  });

  it("flags a GUID excluded from most policies even without a telling name", () => {
    const snap = snapshotWith({
      conditionalAccess: {
        ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].conditionalAccess,
        policies: ["a", "b", "c"].map((id) => ({
          ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].conditionalAccess.policies[1],
          id,
          conditions: { ...MOCK_TENANT_DATA["tenant-woodgrove-fsi"].conditionalAccess.policies[1].conditions, users: { include: ["All"], exclude: ["44444444-4444-4444-4444-444444444444"] } },
        })),
      },
      mfaAudit: [],
    });
    const found = detectLikelyBreakGlassAccounts(snap);
    expect(found).toHaveLength(1);
    expect(found[0].reasons).toEqual(["Excluded from 3 of 3 active policies"]);
  });
});

// End-to-end against the demo tenants: the situations the Sign-in
// Situations view (Stage 3) will run.
describe("demo tenant integration", () => {
  const woodgrove = MOCK_TENANT_DATA["tenant-woodgrove-fsi"];
  const contoso = MOCK_TENANT_DATA["tenant-contoso-corp"];
  const base = (overrides: Partial<SignInContext>): SignInContext => ({
    user: buildSyntheticSimUser("globalAdmin"),
    target: { kind: "resource", resource: "Office365" },
    clientAppType: "browser",
    platform: "windows",
    device: "compliant",
    location: { country: "US", ipNamedLocationIds: [] },
    signInRisk: "none",
    userRisk: "none",
    insiderRisk: "none",
    ...overrides,
  });

  it("Woodgrove: a Global Admin from a foreign country is blocked by CA08", () => {
    const r = evaluateSignIn(base({ location: { country: "RU", ipNamedLocationIds: [] } }), buildCaEnvironment(woodgrove));
    expect(r.enforced.outcome).toBe("blocked");
    expect(r.enforced.blockedBy.map((b) => b.policyId)).toContain("ca-wg-ca08");
  });

  it("Woodgrove: device code flow is blocked by the transfer-flows policy", () => {
    const r = evaluateSignIn(base({ authenticationFlow: "deviceCodeFlow" }), buildCaEnvironment(woodgrove));
    expect(r.enforced.blockedBy.map((b) => b.policyId)).toContain("ca-wg-block-transfer-flows");
  });

  it("Woodgrove: a Global Admin on an unmanaged device is blocked by CA09", () => {
    const r = evaluateSignIn(base({ device: "unmanaged" }), buildCaEnvironment(woodgrove));
    expect(r.enforced.blockedBy.map((b) => b.policyId)).toContain("ca-wg-ca09");
  });

  it("Woodgrove: a Global Admin on a compliant device still needs phishing-resistant MFA (CA10)", () => {
    const r = evaluateSignIn(base({}), buildCaEnvironment(woodgrove));
    expect(r.enforced.outcome).toBe("challenged");
    expect(r.enforced.requirementKinds).toContain("phishingResistantMfa");
  });

  it("Woodgrove: elevated insider risk is only stopped in report-only mode", () => {
    const r = evaluateSignIn(base({ user: buildSyntheticSimUser("user"), insiderRisk: "elevated" }), buildCaEnvironment(woodgrove));
    expect(r.enforced.outcome).not.toBe("blocked");
    expect(r.withReportOnly.outcome).toBe("blocked");
  });

  it("Contoso: a sign-in from a blocked OFAC country is blocked by CA08 via its loc: marker", () => {
    const r = evaluateSignIn(base({ user: buildSyntheticSimUser("user"), location: { country: "KP", ipNamedLocationIds: [] } }), buildCaEnvironment(contoso));
    expect(r.enforced.outcome).toBe("blocked");
  });
});
