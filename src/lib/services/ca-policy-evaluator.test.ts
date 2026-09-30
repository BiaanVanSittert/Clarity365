import { describe, expect, it } from "vitest";
import { CAPolicyRule, CaNamedLocation, TenantGroup } from "../types";
import { CaEnvironment, CaSimUser, SignInContext, evaluateSignIn, tracePolicy } from "./ca-policy-evaluator";
import { GLOBAL_ADMIN_TEMPLATE_ID } from "../utils/directory-role-templates";

// ---------------------------------------------------------------- helpers

const EXCHANGE = "00000002-0000-0ff1-ce00-000000000000";
const SHAREPOINT = "00000003-0000-0ff1-ce00-000000000000";
const AZURE_MGMT = "797f4846-ba00-4fd7-ba43-dac1f8f63013";

function policy(overrides: Partial<Omit<CAPolicyRule, "conditions">> & { conditions?: Partial<CAPolicyRule["conditions"]> } = {}): CAPolicyRule {
  const { conditions, ...rest } = overrides;
  return {
    id: rest.id || "p",
    name: rest.name || "Test policy",
    baselineCode: null,
    state: "enabled",
    modifiedDateTime: "2026-01-01T00:00:00Z",
    createdDateTime: "2026-01-01T00:00:00Z",
    grantControls: ["mfa"],
    matchesBaseline: false,
    ...rest,
    conditions: {
      users: { include: ["All"], exclude: [] },
      applications: { include: ["All"], exclude: [] },
      clientAppTypes: ["all"],
      ...conditions,
    },
  };
}

const standardUser: CaSimUser = {
  id: "11111111-1111-1111-1111-111111111111",
  userPrincipalName: "sam@contoso.com",
  isGuest: false,
  roleTemplateIds: [],
  roleTemplateIdsComplete: true,
  groupIds: [],
};

const globalAdmin: CaSimUser = {
  ...standardUser,
  id: "22222222-2222-2222-2222-222222222222",
  userPrincipalName: "admin@contoso.com",
  roleTemplateIds: [GLOBAL_ADMIN_TEMPLATE_ID],
};

const guest: CaSimUser = {
  ...standardUser,
  id: "33333333-3333-3333-3333-333333333333",
  userPrincipalName: "vendor_fabrikam.com#EXT#@contoso.onmicrosoft.com",
  isGuest: true,
};

function ctx(overrides: Partial<SignInContext> = {}): SignInContext {
  return {
    user: standardUser,
    target: { kind: "resource", resource: "Office365" },
    clientAppType: "browser",
    platform: "windows",
    device: "unmanaged",
    location: { country: "ZA", ipNamedLocationIds: [] },
    signInRisk: "none",
    userRisk: "none",
    insiderRisk: "none",
    ...overrides,
  };
}

function env(policies: CAPolicyRule[], overrides: Partial<CaEnvironment> = {}): CaEnvironment {
  return { policies, namedLocations: [], groups: [], entraP2Licensed: true, ...overrides };
}

const allowedCountries: CaNamedLocation = { id: "loc-allowed", displayName: "Allowed", kind: "country", countries: ["ZA", "US"], includeUnknownCountries: false };
const hqIp: CaNamedLocation = { id: "loc-hq", displayName: "HQ", kind: "ip", ipRanges: ["203.0.113.0/24"], isTrusted: true };

// ------------------------------------------------------------------ tests

describe("users condition", () => {
  it("applies MFA to an in-scope user (challenged)", () => {
    const r = evaluateSignIn(ctx(), env([policy()]));
    expect(r.enforced.outcome).toBe("challenged");
    expect(r.enforced.requirementKinds).toEqual(["mfa"]);
  });

  it("an exclusion by user object id beats an All-users include, and is reported", () => {
    const p = policy({ conditions: { users: { include: ["All"], exclude: [standardUser.id!] } } });
    const t = tracePolicy(p, ctx(), env([p]));
    expect(t.applies).toBe("no");
    expect(t.excludedBy).toEqual([{ kind: "user", ref: standardUser.id }]);
    expect(evaluateSignIn(ctx(), env([p])).enforced.outcome).toBe("allowed");
  });

  it("matches live includeRoles template GUIDs, case-insensitively", () => {
    const p = policy({ conditions: { users: { include: [], exclude: [], includeRoles: [GLOBAL_ADMIN_TEMPLATE_ID.toUpperCase()] } } });
    expect(tracePolicy(p, ctx({ user: globalAdmin }), env([p])).applies).toBe("yes");
    expect(tracePolicy(p, ctx({ user: standardUser }), env([p])).applies).toBe("no");
  });

  it("matches demo/local-write role markers (DirectoryRole:GlobalAdmin, AllAdmins)", () => {
    const marker = policy({ conditions: { users: { include: ["DirectoryRole:GlobalAdmin"], exclude: [] } } });
    const allAdmins = policy({ conditions: { users: { include: ["AllAdmins"], exclude: [] } } });
    expect(tracePolicy(marker, ctx({ user: globalAdmin }), env([marker])).applies).toBe("yes");
    expect(tracePolicy(allAdmins, ctx({ user: globalAdmin }), env([allAdmins])).applies).toBe("yes");
    expect(tracePolicy(allAdmins, ctx({ user: standardUser }), env([allAdmins])).applies).toBe("no");
  });

  it("reports unknown (not a confident no) when the user's roles couldn't all be resolved", () => {
    const p = policy({ conditions: { users: { include: [], exclude: [], includeRoles: [GLOBAL_ADMIN_TEMPLATE_ID] } } });
    const partial = { ...standardUser, roleTemplateIdsComplete: false };
    expect(tracePolicy(p, ctx({ user: partial }), env([p])).applies).toBe("unknown");
    expect(evaluateSignIn(ctx({ user: partial }), env([p])).enforced.outcome).toBe("indeterminate");
  });

  it("targets guests via the GuestsOrExternalUsers marker, respecting guest types", () => {
    const allGuests = policy({ conditions: { users: { include: ["GuestsOrExternalUsers"], exclude: [] } } });
    const directConnectOnly = policy({ conditions: { users: { include: ["GuestsOrExternalUsers"], exclude: [], includeGuestTypes: ["b2bDirectConnectUser"] } } });
    expect(tracePolicy(allGuests, ctx({ user: guest }), env([allGuests])).applies).toBe("yes");
    expect(tracePolicy(allGuests, ctx({ user: standardUser }), env([allGuests])).applies).toBe("no");
    expect(tracePolicy(directConnectOnly, ctx({ user: guest }), env([directConnectOnly])).applies).toBe("no");
  });

  it("a guest is excluded by a GuestsOrExternalUsers exclusion (the real Axiomatic CA02 shape)", () => {
    const p = policy({ conditions: { users: { include: ["All"], exclude: ["GuestsOrExternalUsers"] } } });
    const t = tracePolicy(p, ctx({ user: guest }), env([p]));
    expect(t.applies).toBe("no");
    expect(t.excludedBy).toEqual([{ kind: "guests", ref: "GuestsOrExternalUsers" }]);
  });

  it("resolves group targeting by direct membership (UPN members, as live data stores them)", () => {
    const group: TenantGroup = { id: "grp-1", displayName: "Finance", members: ["sam@contoso.com"] } as TenantGroup;
    const p = policy({ conditions: { users: { include: [], exclude: [], includeGroupIds: ["grp-1"] } } });
    expect(tracePolicy(p, ctx(), env([p], { groups: [group] })).applies).toBe("yes");
    expect(tracePolicy(p, ctx({ user: globalAdmin }), env([p], { groups: [group] })).applies).toBe("no");
  });

  it("treats a group missing from the synced list as unknown, not as a non-member", () => {
    const p = policy({ conditions: { users: { include: [], exclude: [], includeGroupIds: ["grp-not-synced"] } } });
    expect(tracePolicy(p, ctx(), env([p])).applies).toBe("unknown");
  });

  it("never applies a workload-identity policy to a user sign-in", () => {
    const p = policy({ conditions: { users: { include: [], exclude: [] }, clientApplications: { includeServicePrincipals: ["All"], excludeServicePrincipals: [] } } });
    expect(tracePolicy(p, ctx(), env([p])).reason).toMatch(/workload identities/);
  });
});

describe("applications condition", () => {
  it("a policy targeting \"None\" never applies (seen live on a real CA08)", () => {
    const p = policy({ grantControls: ["block"], conditions: { applications: { include: ["None"], exclude: [] } } });
    expect(evaluateSignIn(ctx(), env([p])).enforced.outcome).toBe("allowed");
  });

  it("an Azure management policy doesn't apply to an Office 365 sign-in", () => {
    const p = policy({ conditions: { applications: { include: [AZURE_MGMT], exclude: [] } } });
    expect(tracePolicy(p, ctx(), env([p])).applies).toBe("no");
    expect(tracePolicy(p, ctx({ target: { kind: "resource", resource: "AzureManagement" } }), env([p])).applies).toBe("yes");
  });

  it("a SharePoint-only policy applies to Office 365 with a partial-coverage note", () => {
    const p = policy({ conditions: { applications: { include: [SHAREPOINT], exclude: [] } } });
    const t = tracePolicy(p, ctx(), env([p]));
    expect(t.applies).toBe("yes");
    expect(t.notes.join(" ")).toMatch(/Only covers SharePoint Online/);
  });

  it("excluding Office 365 as a whole takes the policy out of scope", () => {
    const p = policy({ conditions: { applications: { include: ["All"], exclude: ["Office365"] } } });
    expect(tracePolicy(p, ctx(), env([p])).applies).toBe("no");
  });

  it("user-action policies only cover their user action", () => {
    const p = policy({ conditions: { applications: { include: [], exclude: [], userActions: ["urn:user:registersecurityinfo"] } } });
    expect(tracePolicy(p, ctx(), env([p])).applies).toBe("no");
    expect(tracePolicy(p, ctx({ target: { kind: "userAction", action: "urn:user:registersecurityinfo" } }), env([p])).applies).toBe("yes");
    const allApps = policy();
    expect(tracePolicy(allApps, ctx({ target: { kind: "userAction", action: "urn:user:registerdevice" } }), env([allApps])).applies).toBe("no");
  });
});

describe("client app, platform, flows and risk", () => {
  const legacyBlock = policy({ grantControls: ["block"], conditions: { clientAppTypes: ["exchangeActiveSync", "other"] } });

  it("legacy block stops Exchange ActiveSync and other clients but not the browser", () => {
    expect(evaluateSignIn(ctx({ clientAppType: "exchangeActiveSync" }), env([legacyBlock])).enforced.outcome).toBe("blocked");
    expect(evaluateSignIn(ctx({ clientAppType: "other" }), env([legacyBlock])).enforced.outcome).toBe("blocked");
    expect(evaluateSignIn(ctx({ clientAppType: "browser" }), env([legacyBlock])).enforced.outcome).toBe("allowed");
  });

  it("maps the easSupported value to Exchange ActiveSync", () => {
    const p = policy({ grantControls: ["block"], conditions: { clientAppTypes: ["easSupported"] } });
    expect(evaluateSignIn(ctx({ clientAppType: "exchangeActiveSync" }), env([p])).enforced.outcome).toBe("blocked");
  });

  it("platform include/exclude", () => {
    const p = policy({ grantControls: ["block"], conditions: { platforms: { include: ["all"], exclude: ["windows"] } } });
    expect(evaluateSignIn(ctx({ platform: "windows" }), env([p])).enforced.outcome).toBe("allowed");
    expect(evaluateSignIn(ctx({ platform: "macOS" }), env([p])).enforced.outcome).toBe("blocked");
  });

  it("an authentication-flows policy only applies to that flow (the real Microsoft-managed device code block)", () => {
    const p = policy({ grantControls: ["block"], conditions: { authenticationFlows: ["deviceCodeFlow"] } });
    expect(evaluateSignIn(ctx({ authenticationFlow: "deviceCodeFlow" }), env([p])).enforced.outcome).toBe("blocked");
    expect(evaluateSignIn(ctx({ authenticationFlow: "authenticationTransfer" }), env([p])).enforced.outcome).toBe("allowed");
    expect(evaluateSignIn(ctx(), env([p])).enforced.outcome).toBe("allowed");
  });

  it("risk policies apply only at the listed levels, and not at all without Entra ID P2", () => {
    const p = policy({ conditions: { signInRiskLevels: ["medium", "high"] } });
    expect(evaluateSignIn(ctx({ signInRisk: "high" }), env([p])).enforced.outcome).toBe("challenged");
    expect(evaluateSignIn(ctx({ signInRisk: "low" }), env([p])).enforced.outcome).toBe("allowed");
    const unlicensed = tracePolicy(p, ctx({ signInRisk: "high" }), env([p], { entraP2Licensed: false }));
    expect(unlicensed.applies).toBe("no");
    expect(unlicensed.reason).toMatch(/P2/);
  });

  it("risk policies don't apply to guests (their risk is evaluated in their home tenant)", () => {
    const p = policy({ grantControls: ["block"], conditions: { signInRiskLevels: ["high"] } });
    const t = tracePolicy(p, ctx({ user: guest, signInRisk: "high" }), env([p]));
    expect(t.applies).toBe("no");
    expect(t.reason).toMatch(/home organization/);
  });

  it("insider risk levels, with a licensing note", () => {
    const p = policy({ grantControls: ["block"], conditions: { insiderRiskLevels: ["elevated"] } });
    const r = evaluateSignIn(ctx({ insiderRisk: "elevated" }), env([p]));
    expect(r.enforced.outcome).toBe("blocked");
    expect(r.trace[0].notes.join(" ")).toMatch(/Insider Risk Management/);
  });

  it("a device filter makes the policy indeterminate rather than guessed", () => {
    const p = policy({ grantControls: ["block"], conditions: { deviceFilter: { mode: "exclude", rule: 'device.trustType -eq "ServerAD"' } } });
    expect(evaluateSignIn(ctx(), env([p])).enforced.outcome).toBe("indeterminate");
  });
});

describe("locations", () => {
  const countryBlock = policy({ grantControls: ["block"], conditions: { locations: { include: ["All"], exclude: ["loc-allowed"] } } });

  it("blocks a sign-in from outside the allowed countries (the real CA08 shape)", () => {
    const e = env([countryBlock], { namedLocations: [allowedCountries] });
    expect(evaluateSignIn(ctx({ location: { country: "RU", ipNamedLocationIds: [] } }), e).enforced.outcome).toBe("blocked");
    expect(evaluateSignIn(ctx({ location: { country: "ZA", ipNamedLocationIds: [] } }), e).enforced.outcome).toBe("allowed");
  });

  it("treats an unmappable country according to includeUnknownCountries", () => {
    const e = env([countryBlock], { namedLocations: [allowedCountries] });
    expect(evaluateSignIn(ctx({ location: { country: null, ipNamedLocationIds: [] } }), e).enforced.outcome).toBe("blocked");
  });

  it("is indeterminate when named locations were never synced", () => {
    const r = evaluateSignIn(ctx({ location: { country: "RU", ipNamedLocationIds: [] } }), env([countryBlock], { namedLocations: undefined }));
    expect(r.enforced.outcome).toBe("indeterminate");
    expect(r.notes.join(" ")).toMatch(/Named locations haven't been synced/);
  });

  it("AllTrusted matches trusted IP named locations", () => {
    const p = policy({ conditions: { locations: { include: ["All"], exclude: ["AllTrusted"] } } });
    const e = env([p], { namedLocations: [hqIp] });
    expect(evaluateSignIn(ctx({ location: { country: "ZA", ipNamedLocationIds: ["loc-hq"] } }), e).enforced.outcome).toBe("allowed");
    expect(evaluateSignIn(ctx({ location: { country: "ZA", ipNamedLocationIds: [] } }), e).enforced.outcome).toBe("challenged");
  });

  it("resolves demo \"loc:\" marker ids like any other named location id", () => {
    const p = policy({ grantControls: ["block"], conditions: { locations: { include: ["loc:Blocked"], exclude: [] } } });
    const e = env([p], { namedLocations: [{ id: "loc:Blocked", displayName: "Blocked", kind: "country", countries: ["KP"] }] });
    expect(evaluateSignIn(ctx({ location: { country: "KP", ipNamedLocationIds: [] } }), e).enforced.outcome).toBe("blocked");
  });
});

describe("grant controls", () => {
  it("compliant device OR hybrid join: unmanaged is blocked, compliant passes silently", () => {
    const p = policy({ grantControls: ["compliantDevice", "domainJoinedDevice"], grantOperator: "OR" });
    const blocked = evaluateSignIn(ctx({ device: "unmanaged" }), env([p]));
    expect(blocked.enforced.outcome).toBe("blocked");
    expect(blocked.enforced.blockedBy[0].reason).toMatch(/compliant device/);
    expect(evaluateSignIn(ctx({ device: "compliant" }), env([p])).enforced.outcome).toBe("allowed");
    expect(evaluateSignIn(ctx({ device: "hybridJoined" }), env([p])).enforced.outcome).toBe("allowed");
  });

  it("MFA OR compliant device: a compliant device satisfies it without MFA", () => {
    const p = policy({ grantControls: ["mfa", "compliantDevice"], grantOperator: "OR" });
    expect(evaluateSignIn(ctx({ device: "compliant" }), env([p])).enforced.outcome).toBe("allowed");
    expect(evaluateSignIn(ctx({ device: "unmanaged" }), env([p])).enforced.outcome).toBe("challenged");
  });

  it("MFA AND compliant device: an unmanaged device is blocked", () => {
    const p = policy({ grantControls: ["mfa", "compliantDevice"], grantOperator: "AND" });
    expect(evaluateSignIn(ctx({ device: "unmanaged" }), env([p])).enforced.outcome).toBe("blocked");
    const compliant = evaluateSignIn(ctx({ device: "compliant" }), env([p]));
    expect(compliant.enforced.outcome).toBe("challenged");
    expect(compliant.enforced.requirementKinds).toEqual(["mfa"]);
  });

  it("an unsynced operator is assumed AND with password change, OR otherwise, with a note", () => {
    const riskPolicy = policy({ grantControls: ["mfa", "passwordChange"], conditions: { userRiskLevels: ["high"] } });
    const r = evaluateSignIn(ctx({ userRisk: "high" }), env([riskPolicy]));
    expect(r.enforced.requirements[0].paths).toEqual([[{ kind: "mfa", label: "Multifactor authentication" }, { kind: "passwordChange", label: "Secure password change" }]]);
    expect(r.trace[0].notes.join(" ")).toMatch(/assumed "require all of"/);
  });

  it("approved app / app protection: possible from a mobile app, blocked from Windows", () => {
    const p = policy({ grantControls: ["approvedApplication", "appProtectionPolicy"], grantOperator: "OR" });
    const ios = evaluateSignIn(ctx({ platform: "iOS", clientAppType: "mobileAppsAndDesktopClients" }), env([p]));
    expect(ios.enforced.outcome).toBe("challenged");
    expect(ios.enforced.requirementKinds).toEqual(["appProtection"]);
    expect(evaluateSignIn(ctx({ platform: "windows" }), env([p])).enforced.outcome).toBe("blocked");
  });

  it("treats Microsoft's risk remediation grant as a remediation requirement", () => {
    const p = policy({ grantControls: ["riskRemediation", "authenticationStrength:Multifactor authentication"], grantOperator: "AND", conditions: { userRiskLevels: ["high"] } });
    const r = evaluateSignIn(ctx({ userRisk: "high" }), env([p]));
    expect(r.enforced.requirementKinds).toEqual(["passwordChange", "authenticationStrength"]);
  });

  it("recognises phishing-resistant authentication strength", () => {
    const p = policy({ grantControls: ["authenticationStrength:Phishing-resistant MFA"] });
    expect(evaluateSignIn(ctx(), env([p])).enforced.requirementKinds).toEqual(["phishingResistantMfa"]);
  });

  it("block wins over every other policy", () => {
    const r = evaluateSignIn(ctx(), env([policy({ id: "a" }), policy({ id: "b", grantControls: ["block"] })]));
    expect(r.enforced.outcome).toBe("blocked");
    expect(r.enforced.blockedBy.map((b) => b.policyId)).toEqual(["b"]);
  });

  it("records session controls from applying policies", () => {
    const p = policy({ sessionControls: { signInFrequency: { isEnabled: true, value: 4, type: "hours" }, tokenProtection: true } });
    expect(evaluateSignIn(ctx(), env([p])).enforced.sessionControls[0].controls).toEqual(["Sign-in frequency: 4 hours", "Token protection"]);
  });
});

describe("policy states", () => {
  it("report-only policies don't change the enforced outcome but are reported", () => {
    const p = policy({ state: "enabledForReportingButNotEnforced", grantControls: ["block"] });
    const r = evaluateSignIn(ctx(), env([p]));
    expect(r.enforced.outcome).toBe("allowed");
    expect(r.withReportOnly.outcome).toBe("blocked");
    expect(r.reportOnlyHits.map((h) => h.policyId)).toEqual(["p"]);
  });

  it("disabled policies never apply", () => {
    const p = policy({ state: "disabled", grantControls: ["block"] });
    const r = evaluateSignIn(ctx(), env([p]));
    expect(r.enforced.outcome).toBe("allowed");
    expect(r.trace[0].reason).toBe("Policy is disabled");
  });

  it("models security defaults when they're on and no CA policy is enabled", () => {
    const e = env([], { securityDefaultsEnabled: true });
    expect(evaluateSignIn(ctx({ clientAppType: "exchangeActiveSync" }), e).enforced.outcome).toBe("blocked");
    const admin = evaluateSignIn(ctx({ user: globalAdmin }), e);
    expect(admin.enforced.outcome).toBe("challenged");
    expect(admin.evaluatedWithSecurityDefaults).toBe(true);
  });
});

describe("policies synced before simulation support", () => {
  it("evaluates them as unknown instead of guessing (regression: a real device-code block read as block-everything)", () => {
    // The live Zubat Nine shape after an old-code sync: authenticationFlows dropped.
    const deviceCodeBlock = policy({ id: "ms-managed", name: "Microsoft-managed: Block device code flow", grantControls: ["block"] });
    const r = evaluateSignIn(ctx(), env([deviceCodeBlock], { incompletePolicyIds: ["ms-managed"] }));
    expect(r.enforced.outcome).toBe("indeterminate");
    expect(r.trace[0].reason).toMatch(/Re-sync/);
    expect(r.notes.join(" ")).toMatch(/1 policies were synced before simulation support/);
  });

  it("still reports disabled incomplete policies as disabled", () => {
    const p = policy({ id: "x", state: "disabled", grantControls: ["block"] });
    expect(tracePolicy(p, ctx(), env([p], { incompletePolicyIds: ["x"] })).reason).toBe("Policy is disabled");
  });
});

describe("real Exchange/SharePoint app ids", () => {
  it("an Exchange-only block still blocks an Office 365 sign-in", () => {
    const p = policy({ grantControls: ["block"], conditions: { applications: { include: [EXCHANGE], exclude: [] } } });
    expect(evaluateSignIn(ctx(), env([p])).enforced.outcome).toBe("blocked");
  });
});
