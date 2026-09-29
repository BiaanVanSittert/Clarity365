import { describe, expect, it } from "vitest";
import {
  applyCaBetaSessionExtras,
  deriveUserConsentMode,
  mapCaBetaSessionExtras,
  mapCaPolicyExtendedFields,
  mapCaSessionControls,
  mapNamedLocation,
  mapTenantIdentitySettings,
  splitGraphFlags,
} from "./ca-environment-mapper";
import { mapConditionalAccessPolicy } from "./graph-client";
import { CAPolicyRule } from "../types";

describe("splitGraphFlags", () => {
  it("splits Graph's comma-separated flags strings and drops none/unknownFutureValue", () => {
    expect(splitGraphFlags("deviceCodeFlow,authenticationTransfer")).toEqual(["deviceCodeFlow", "authenticationTransfer"]);
    expect(splitGraphFlags("minor, moderate ,elevated")).toEqual(["minor", "moderate", "elevated"]);
    expect(splitGraphFlags("none")).toEqual([]);
    expect(splitGraphFlags(null)).toEqual([]);
    expect(splitGraphFlags(["elevated"])).toEqual(["elevated"]);
  });
});

describe("mapCaPolicyExtendedFields", () => {
  const raw = {
    id: "p1",
    conditions: {
      users: {
        includeUsers: [],
        includeGroups: ["grp-finance"],
        excludeGroups: ["grp-breakglass"],
        includeRoles: [],
        excludeRoles: ["d29b2b05-8046-44ba-8758-1e26182fcf32"],
        includeGuestsOrExternalUsers: { guestOrExternalUserTypes: "b2bCollaborationGuest,b2bCollaborationMember", externalTenants: { membershipKind: "all" } },
        excludeGuestsOrExternalUsers: null,
      },
      applications: {
        includeApplications: [],
        includeUserActions: ["urn:user:registersecurityinfo"],
        includeAuthenticationContextClassReferences: ["c1"],
      },
      authenticationFlows: { transferMethods: "deviceCodeFlow,authenticationTransfer" },
      insiderRiskLevels: "elevated",
      devices: { deviceFilter: { mode: "exclude", rule: 'device.trustType -eq "ServerAD"' } },
      clientApplications: null,
      servicePrincipalRiskLevels: [],
    },
    grantControls: { operator: "AND", builtInControls: ["mfa", "compliantDevice"] },
    sessionControls: null,
  };

  it("keeps every field the original mapper dropped", () => {
    const ext = mapCaPolicyExtendedFields(raw);
    expect(ext.users.includeGroupIds).toEqual(["grp-finance"]);
    expect(ext.users.excludeRoles).toEqual(["d29b2b05-8046-44ba-8758-1e26182fcf32"]);
    expect(ext.users.includeGuestTypes).toEqual(["b2bCollaborationGuest", "b2bCollaborationMember"]);
    expect(ext.users.excludeGuestTypes).toEqual([]);
    expect(ext.applications.userActions).toEqual(["urn:user:registersecurityinfo"]);
    expect(ext.applications.authenticationContexts).toEqual(["c1"]);
    expect(ext.conditions.authenticationFlows).toEqual(["deviceCodeFlow", "authenticationTransfer"]);
    expect(ext.conditions.insiderRiskLevels).toEqual(["elevated"]);
    expect(ext.conditions.deviceFilter).toEqual({ mode: "exclude", rule: 'device.trustType -eq "ServerAD"' });
    expect(ext.conditions.clientApplications).toBeUndefined();
    expect(ext.grantOperator).toBe("AND");
    expect(ext.sessionControls).toBeUndefined();
  });

  it("is carried through mapConditionalAccessPolicy without disturbing the existing fields", () => {
    const mapped = mapConditionalAccessPolicy({ ...raw, displayName: "Finance MFA", state: "enabled" });
    expect(mapped.conditions.users.includeGroupIds).toEqual(["grp-finance"]);
    expect(mapped.conditions.users.excludeGroupIds).toEqual(["grp-breakglass"]);
    // The existing guest marker convention still holds alongside the new guest types.
    expect(mapped.conditions.users.include).toContain("GuestsOrExternalUsers");
    expect(mapped.conditions.applications.userActions).toEqual(["urn:user:registersecurityinfo"]);
    expect(mapped.conditions.authenticationFlows).toEqual(["deviceCodeFlow", "authenticationTransfer"]);
    expect(mapped.grantOperator).toBe("AND");
    expect(mapped.grantControls).toEqual(["mfa", "compliantDevice"]);
  });

  it("leaves grantOperator undefined when Graph omits it or sends an unexpected value", () => {
    expect(mapCaPolicyExtendedFields({ grantControls: null }).grantOperator).toBeUndefined();
    expect(mapCaPolicyExtendedFields({ grantControls: { operator: "XOR" } }).grantOperator).toBeUndefined();
  });
});

describe("mapCaSessionControls", () => {
  it("maps the five v1.0 session controls", () => {
    const sc = mapCaSessionControls({
      applicationEnforcedRestrictions: { isEnabled: true },
      cloudAppSecurity: { isEnabled: true, cloudAppSecurityType: "monitorOnly" },
      persistentBrowser: { isEnabled: true, mode: "never" },
      signInFrequency: { isEnabled: true, value: 4, type: "hours", frequencyInterval: "timeBased", authenticationType: "primaryAndSecondaryAuthentication" },
      disableResilienceDefaults: false,
    });
    expect(sc).toEqual({
      applicationEnforcedRestrictions: true,
      cloudAppSecurity: { isEnabled: true, type: "monitorOnly" },
      persistentBrowser: { isEnabled: true, mode: "never" },
      signInFrequency: { isEnabled: true, value: 4, type: "hours", frequencyInterval: "timeBased", authenticationType: "primaryAndSecondaryAuthentication" },
      disableResilienceDefaults: false,
    });
  });

  it("returns undefined for null or all-null session controls", () => {
    expect(mapCaSessionControls(null)).toBeUndefined();
    expect(mapCaSessionControls({ applicationEnforcedRestrictions: null, signInFrequency: null })).toBeUndefined();
  });
});

describe("beta session extras", () => {
  it("reads token protection and CAE mode, leaving absent keys undefined (not false)", () => {
    expect(mapCaBetaSessionExtras({ sessionControls: { secureSignInSession: { isEnabled: true }, continuousAccessEvaluation: { mode: "strictLocation" } } })).toEqual({
      tokenProtection: true,
      continuousAccessEvaluation: "strictLocation",
    });
    expect(mapCaBetaSessionExtras({ sessionControls: { signInFrequency: { isEnabled: true } } })).toEqual({});
    expect(mapCaBetaSessionExtras({ sessionControls: null })).toEqual({});
  });

  it("merges extras by policy id without dropping v1.0 session controls", () => {
    const policies = [
      { id: "a", sessionControls: { signInFrequency: { isEnabled: true, value: 1, type: "hours" } } },
      { id: "b" },
    ] as unknown as CAPolicyRule[];
    const merged = applyCaBetaSessionExtras(policies, new Map([["a", { tokenProtection: true }], ["b", {}]]));
    expect(merged[0].sessionControls).toEqual({ signInFrequency: { isEnabled: true, value: 1, type: "hours" }, tokenProtection: true });
    expect(merged[1]).toBe(policies[1]);
  });
});

describe("mapNamedLocation", () => {
  it("maps a country location, upper-casing codes", () => {
    expect(
      mapNamedLocation({
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        id: "loc-1",
        displayName: "Blocked countries",
        countriesAndRegions: ["ru", "KP"],
        includeUnknownCountriesAndRegions: true,
        countryLookupMethod: "clientIpAddress",
      })
    ).toEqual({
      id: "loc-1",
      displayName: "Blocked countries",
      kind: "country",
      countries: ["RU", "KP"],
      includeUnknownCountries: true,
      countryLookupMethod: "clientIpAddress",
    });
  });

  it("maps an IP location with its trusted flag", () => {
    expect(
      mapNamedLocation({
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        id: "loc-2",
        displayName: "HQ",
        isTrusted: true,
        ipRanges: [{ "@odata.type": "#microsoft.graph.iPv4CidrRange", cidrAddress: "203.0.113.0/24" }],
      })
    ).toEqual({ id: "loc-2", displayName: "HQ", kind: "ip", ipRanges: ["203.0.113.0/24"], isTrusted: true });
  });

  it("drops unknown location types instead of guessing", () => {
    expect(mapNamedLocation({ "@odata.type": "#microsoft.graph.somethingNew", id: "x" })).toBeNull();
    expect(mapNamedLocation({})).toBeNull();
  });
});

describe("tenant identity settings", () => {
  it("derives user consent mode from ManagePermissionGrantsForSelf entries only", () => {
    expect(deriveUserConsentMode([])).toBe("disabled");
    // Group-owner consent only - end users still cannot consent.
    expect(deriveUserConsentMode(["ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team"])).toBe("disabled");
    expect(deriveUserConsentMode(["ManagePermissionGrantsForSelf.microsoft-user-default-low"])).toBe("verifiedPublishersLowRisk");
    expect(deriveUserConsentMode(["ManagePermissionGrantsForSelf.microsoft-user-default-recommended"])).toBe("microsoftRecommended");
    expect(deriveUserConsentMode(["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"])).toBe("allApps");
    expect(deriveUserConsentMode(["ManagePermissionGrantsForSelf.contoso-custom"])).toBe("custom");
  });

  it("maps all three policy reads", () => {
    expect(
      mapTenantIdentitySettings(
        { isEnabled: false },
        {
          allowInvitesFrom: "adminsAndGuestInviters",
          guestUserRoleId: "2af84b1e-32c8-42b7-82bc-daa82404023b",
          defaultUserRolePermissions: { permissionGrantPoliciesAssigned: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] },
        },
        { isEnabled: true }
      )
    ).toEqual({
      securityDefaultsEnabled: false,
      userConsentPolicies: ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"],
      userConsentMode: "allApps",
      guestAccessLevel: "restricted",
      guestInviteSetting: "adminsAndGuestInviters",
      adminConsentWorkflowEnabled: true,
    });
  });

  it("leaves a failed read's fields undefined rather than defaulting them", () => {
    const settings = mapTenantIdentitySettings(undefined, undefined, { isEnabled: false });
    expect(settings).toEqual({ adminConsentWorkflowEnabled: false });
    expect(settings.securityDefaultsEnabled).toBeUndefined();
  });

  it("reports unrecognised guest role ids and invite values as unknown", () => {
    const settings = mapTenantIdentitySettings(undefined, { guestUserRoleId: "00000000-0000-0000-0000-000000000000", allowInvitesFrom: "somethingNew" }, undefined);
    expect(settings.guestAccessLevel).toBe("unknown");
    expect(settings.guestInviteSetting).toBe("unknown");
  });
});
