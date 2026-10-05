import { describe, expect, it } from "vitest";
import { previewPolicyImpact, clientAppTypeOf, platformOf, deviceStateOf, describePolicyImpact } from "./ca-policy-impact";
import { mapConditionalAccessPolicy } from "./ca-policy-mapper";
import { buildFixGuide, buildFixGuideContext, mapProposedPolicy, previewProposedPolicy } from "./scenario-fix-guide-builder";
import { FIX_GUIDES, caCreateScript } from "../data/scenario-fix-guides";
import { evaluateScenarios } from "./security-scenarios";
import { MOCK_TENANT_DATA } from "../data/mock-tenants";
import { SignInEvent, TenantSecuritySnapshot } from "../types";

const GA = "62e90394-69f5-4237-9190-012177145e10";
const ADMIN_ID = "aaaaaaaa-0000-0000-0000-000000000001";
const USER_ID = "aaaaaaaa-0000-0000-0000-000000000002";
const BREAK_GLASS = "aaaaaaaa-0000-0000-0000-000000000003";

function signIn(over: Partial<SignInEvent> & { country?: string }): SignInEvent {
  const { country, ...rest } = over;
  return {
    id: Math.random().toString(36),
    createdDateTime: "2026-10-01T08:00:00Z",
    userPrincipalName: "ann@contoso.com",
    userDisplayName: "Ann",
    userId: USER_ID,
    ipAddress: "198.51.100.7",
    location: { city: "", state: "", country: country || "ZA" },
    clientApp: "Browser",
    appDisplayName: "Office 365",
    status: "success",
    errorCode: 0,
    isRisky: false,
    riskLevel: "none",
    deviceDetail: { operatingSystem: "Windows 11", browser: "Edge", isCompliant: false, isManaged: false },
    appliedConditionalAccessPolicies: [],
    ...rest,
  } as SignInEvent;
}

function snapshot(signIns: SignInEvent[]): TenantSecuritySnapshot {
  return {
    tenant: { id: "t1", displayName: "Contoso", defaultDomainName: "contoso.com", credentials: { tenantId: "tenant-guid", clientId: "x", authMode: "secret" } },
    conditionalAccess: { policies: [], namedLocations: [] },
    mfaAudit: [
      { id: ADMIN_ID, userPrincipalName: "admin@contoso.com", displayName: "Admin", isAdmin: true, adminRoleTemplateIds: [GA] },
      { id: USER_ID, userPrincipalName: "ann@contoso.com", displayName: "Ann", isAdmin: false },
    ],
    signIns,
  } as unknown as TenantSecuritySnapshot;
}

describe("sign-in field mapping", () => {
  it("maps the sign-in log's client app, OS and device to What If values", () => {
    expect(clientAppTypeOf("Browser")).toBe("browser");
    expect(clientAppTypeOf("Mobile Apps and Desktop clients")).toBe("mobileAppsAndDesktopClients");
    expect(clientAppTypeOf("Exchange ActiveSync")).toBe("exchangeActiveSync");
    expect(clientAppTypeOf("IMAP4")).toBe("other");
    expect(platformOf("MacOs")).toBe("macOS");
    expect(platformOf("Ios")).toBe("iOS");
    expect(deviceStateOf({ operatingSystem: "Windows", browser: "", isCompliant: false, isManaged: true, trustType: "Hybrid Azure AD joined" })).toBe("hybridJoined");
  });
});

describe("previewPolicyImpact", () => {
  it("counts blocked sign-ins and names the users", () => {
    const snap = snapshot([signIn({ clientApp: "IMAP4" }), signIn({ clientApp: "Browser" }), signIn({ clientApp: "Exchange ActiveSync", status: "failure" } as any)]);
    const rule = mapConditionalAccessPolicy({
      id: "p",
      displayName: "Block legacy",
      state: "enabledForReportingButNotEnforced",
      conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["exchangeActiveSync", "other"] },
      grantControls: { operator: "OR", builtInControls: ["block"] },
    });
    const r = previewPolicyImpact(snap, rule);
    // The failed sign-in isn't replayed.
    expect(r).toMatchObject({ checked: 2, blocked: 1, blockedUsers: ["ann@contoso.com"], challenged: 0, unaffected: 1 });
  });

  it("doesn't count an MFA requirement the sign-in already met", () => {
    const snap = snapshot([
      signIn({ authentication: { requirement: "multiFactor", methods: ["Password", "Mobile app notification"], fromExistingSession: false } }),
      signIn({ authentication: { requirement: "singleFactor", methods: ["Password"], fromExistingSession: false } }),
    ]);
    const rule = mapConditionalAccessPolicy({
      id: "p",
      displayName: "MFA",
      state: "enabled",
      conditions: { users: { includeUsers: ["All"] }, applications: { includeApplications: ["All"] }, clientAppTypes: ["all"] },
      grantControls: { operator: "OR", builtInControls: ["mfa"] },
    });
    expect(previewPolicyImpact(snap, rule)).toMatchObject({ checked: 2, alreadyMet: 1, challenged: 1, challengeKinds: ["mfa"], unaffected: 0 });
  });
});

describe("Conditional Access guides", () => {
  it("blocks the foreign sign-in, but not the home-country one, in the country preview", () => {
    const snap = snapshot([signIn({}), signIn({}), signIn({ country: "NL", userId: ADMIN_ID, userPrincipalName: "admin@contoso.com" })]);
    const ctx = buildFixGuideContext("block-foreign-countries", snap);
    expect(ctx.homeCountry).toBe("ZA");
    expect(ctx.observedCountries).toEqual([{ code: "NL", count: 1 }]);
    const g = buildFixGuide("block-foreign-countries", snap)!;
    expect(g.preview).toMatchObject({ available: true, result: { checked: 3, blocked: 1, blockedUsers: ["admin@contoso.com"] } });
    expect(g.steps[0].note).toContain("NL (1)");
  });

  it("writes the named location first and points the policy at it", () => {
    const def = FIX_GUIDES.find((g) => g.id === "block-foreign-countries")!;
    const script = caCreateScript(def.proposedPolicy!({ tenantName: "x", breakGlass: [{ objectId: BREAK_GLASS, label: "bg" }], items: [], homeCountry: "ZA", observedCountries: [] }));
    expect(script.startsWith("$location = New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{")).toBe(true);
    expect(script).toContain(`"@odata.type" = '#microsoft.graph.countryNamedLocation'`);
    expect(script).toContain("countriesAndRegions = @('ZA')");
    expect(script).toContain("excludeLocations = @($location.Id)");
    expect(script).toContain(`excludeUsers = @('${BREAK_GLASS}')`);
    expect(script).not.toContain("{{NEW_LOCATION_ID}}");
    expect(script.trim().endsWith("New-MgIdentityConditionalAccessPolicy -BodyParameter $policy")).toBe(true);
  });

  it("uses the beta module for token protection", () => {
    const g = buildFixGuide("require-token-protection", snapshot([signIn({})]))!;
    const cmd = g.steps.find((s) => s.command)!.command!;
    expect(cmd.shell).toBe("MicrosoftGraphBeta");
    expect(cmd.install).toBe("Install-Module Microsoft.Graph.Beta");
    expect(cmd.script).toContain("New-MgBetaIdentityConditionalAccessPolicy");
    expect(cmd.script).toContain("secureSignInSession");
    expect(g.preview).toMatchObject({ available: false });
  });

  it("explains why there is no preview when nothing has been synced", () => {
    expect(buildFixGuide("require-mfa-all-users", snapshot([]))!.preview).toEqual({ available: false, reason: "No successful sign-ins have been synced for this tenant yet." });
  });

  it("describes the preview in plain sentences, flagging sign-ins that don't record their methods", () => {
    const snap = snapshot([signIn({}), signIn({ authentication: { requirement: "singleFactor", methods: ["Password"], fromExistingSession: false } }), signIn({ authentication: { requirement: "multiFactor", methods: ["Mobile app notification"], fromExistingSession: false } })]);
    const g = buildFixGuide("require-mfa-all-users", snap)!;
    if (!g.preview?.available) throw new Error("expected a preview");
    expect(describePolicyImpact(g.preview.result)).toEqual({
      headline: "Replayed 3 successful sign-ins from 1 Oct 2026 to 1 Oct 2026 against this policy, as if it were on.",
      lines: [
        "2 sign-ins would have needed MFA (ann@contoso.com).",
        "1 of these doesn't record how the user signed in (they were synced before Clarity365 read that), so some may already have done it. Re-sync for exact numbers.",
        "1 sign-in already met what the policy asks for.",
      ],
    });
  });

  it("asks admins for phishing-resistant MFA unless they already used it", () => {
    const admin = { userId: ADMIN_ID, userPrincipalName: "admin@contoso.com" };
    const snap = snapshot([
      signIn({ ...admin, authentication: { requirement: "multiFactor", methods: ["Mobile app notification"], fromExistingSession: false } }),
      signIn({ ...admin, authentication: { requirement: "multiFactor", methods: ["Passkey (device-bound)"], fromExistingSession: false } }),
      signIn({}),
    ]);
    const proposed = FIX_GUIDES.find((g) => g.id === "require-phishing-resistant-admins")!.proposedPolicy!(buildFixGuideContext("require-phishing-resistant-admins", snap));
    expect(previewProposedPolicy(proposed, snap)).toMatchObject({ available: true, result: { challenged: 1, alreadyMet: 1, unaffected: 1, challengeKinds: ["phishingResistantMfa"] } });
  });
});

// The strongest check on a guide: once its policy is switched on, does the
// scenario check it is offered on turn green? Run against every demo tenant
// with that tenant's own policies removed, so only the guide's policy counts.
describe("each Conditional Access guide fixes the checks that offer it", () => {
  const caGuides = FIX_GUIDES.filter((g) => g.proposedPolicy);
  for (const g of caGuides) {
    it(g.id, () => {
      let compared = 0;
      for (const base of Object.values(MOCK_TENANT_DATA)) {
        const empty = { ...base, conditionalAccess: { ...(base.conditionalAccess || { policies: [] }), policies: [] } } as TenantSecuritySnapshot;
        const offered = evaluateScenarios(empty).flatMap((r) => r.checks.filter((c) => c.guideId === g.id).map((c) => `${r.id}/${c.id}`));
        if (offered.length === 0) continue;
        const proposed = g.proposedPolicy!(buildFixGuideContext(g.id, empty));
        const locationId = "11111111-1111-1111-1111-111111111111";
        const body = JSON.parse(JSON.stringify(proposed.body).split("{{NEW_LOCATION_ID}}").join(locationId));
        const rule = { ...mapProposedPolicy(body), state: "enabled" as const };
        const namedLocations = [...(empty.conditionalAccess?.namedLocations || []), ...(proposed.namedLocation ? [{ ...proposed.namedLocation.preview, id: locationId }] : [])];
        const fixed = { ...empty, conditionalAccess: { ...empty.conditionalAccess!, policies: [rule], namedLocations } } as TenantSecuritySnapshot;
        const after = new Map<string, { status: string; detail?: string }>(evaluateScenarios(fixed).flatMap((r) => r.checks.map((c) => [`${r.id}/${c.id}`, c] as const)));
        for (const key of offered) {
          compared++;
          expect(after.get(key)?.status, `${base.tenant.displayName}: ${key} -> ${after.get(key)?.detail}`).not.toBe("notPrevented");
        }
      }
      expect(compared, "no demo tenant offers this guide").toBeGreaterThan(0);
    });
  }
});
