import { CaNamedLocation, CaSessionControls, CAPolicyRule, TenantIdentitySettings } from "../types";

// Pure Graph -> domain mappers for the Conditional Access "environment" the
// Security Simulations engine needs beyond the policy list itself: the
// policy fields mapConditionalAccessPolicy() used to drop, named locations,
// and the tenant-wide identity settings. Imports only ../types, like every
// other file in ai-context-vault/Services/Data Mappers.md.

// Graph returns several CA "flags" enums as one comma-separated string
// (authenticationFlows.transferMethods, insiderRiskLevels,
// guestOrExternalUserTypes) - normalize to a clean array.
export function splitGraphFlags(value: unknown): string[] {
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string" && v.length > 0);
  if (typeof value !== "string") return [];
  return value
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0 && v !== "none" && v !== "unknownFutureValue");
}

// The parts of CAPolicyRule that the original mapper didn't carry. Returned
// as a partial so mapConditionalAccessPolicy() can spread it in without
// restating the fields it already maps.
export function mapCaPolicyExtendedFields(p: any): {
  users: Pick<CAPolicyRule["conditions"]["users"], "includeGroupIds" | "excludeRoles" | "includeGuestTypes" | "excludeGuestTypes">;
  applications: Pick<CAPolicyRule["conditions"]["applications"], "userActions" | "authenticationContexts">;
  conditions: Pick<
    CAPolicyRule["conditions"],
    "authenticationFlows" | "insiderRiskLevels" | "deviceFilter" | "clientApplications" | "servicePrincipalRiskLevels"
  >;
  grantOperator?: "AND" | "OR";
  sessionControls?: CaSessionControls;
} {
  const c = p?.conditions || {};
  const users = c.users || {};
  const apps = c.applications || {};

  const deviceFilterRaw = c.devices?.deviceFilter;
  const deviceFilter =
    deviceFilterRaw && typeof deviceFilterRaw.rule === "string" && deviceFilterRaw.rule.length > 0
      ? { mode: (deviceFilterRaw.mode === "exclude" ? "exclude" : "include") as "include" | "exclude", rule: deviceFilterRaw.rule }
      : undefined;

  const clientApplications = c.clientApplications
    ? {
        includeServicePrincipals: c.clientApplications.includeServicePrincipals || [],
        excludeServicePrincipals: c.clientApplications.excludeServicePrincipals || [],
      }
    : undefined;

  // Case-insensitive: Microsoft's own documented examples send "and"/"or" in
  // lower case (confirmed on the workload-identity Learn page, 2026-09-30).
  const operatorRaw = typeof p?.grantControls?.operator === "string" ? p.grantControls.operator.toUpperCase() : undefined;
  const grantOperator = operatorRaw === "AND" || operatorRaw === "OR" ? operatorRaw : undefined;

  return {
    users: {
      includeGroupIds: users.includeGroups || [],
      excludeRoles: users.excludeRoles || [],
      includeGuestTypes: splitGraphFlags(users.includeGuestsOrExternalUsers?.guestOrExternalUserTypes),
      excludeGuestTypes: splitGraphFlags(users.excludeGuestsOrExternalUsers?.guestOrExternalUserTypes),
    },
    applications: {
      userActions: apps.includeUserActions || [],
      authenticationContexts: apps.includeAuthenticationContextClassReferences || [],
    },
    conditions: {
      authenticationFlows: splitGraphFlags(c.authenticationFlows?.transferMethods),
      insiderRiskLevels: splitGraphFlags(c.insiderRiskLevels),
      deviceFilter,
      clientApplications,
      servicePrincipalRiskLevels: c.servicePrincipalRiskLevels || [],
    },
    grantOperator,
    sessionControls: mapCaSessionControls(p?.sessionControls),
  };
}

// v1.0 sessionControls. Graph returns null (not an absent key) for a policy
// with no session controls - map that to undefined so "no session controls"
// and "not synced" read the same way to consumers that only need presence.
export function mapCaSessionControls(raw: any): CaSessionControls | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const out: CaSessionControls = {};

  if (raw.signInFrequency) {
    const sif = raw.signInFrequency;
    out.signInFrequency = {
      isEnabled: !!sif.isEnabled,
      value: typeof sif.value === "number" ? sif.value : undefined,
      type: sif.type === "hours" || sif.type === "days" ? sif.type : undefined,
      frequencyInterval: sif.frequencyInterval === "everyTime" ? "everyTime" : sif.frequencyInterval === "timeBased" ? "timeBased" : undefined,
      authenticationType: sif.authenticationType || undefined,
    };
  }
  if (raw.persistentBrowser) {
    out.persistentBrowser = {
      isEnabled: !!raw.persistentBrowser.isEnabled,
      mode: raw.persistentBrowser.mode === "always" || raw.persistentBrowser.mode === "never" ? raw.persistentBrowser.mode : undefined,
    };
  }
  if (raw.applicationEnforcedRestrictions) {
    out.applicationEnforcedRestrictions = !!raw.applicationEnforcedRestrictions.isEnabled;
  }
  if (raw.cloudAppSecurity) {
    out.cloudAppSecurity = {
      isEnabled: !!raw.cloudAppSecurity.isEnabled,
      type: raw.cloudAppSecurity.cloudAppSecurityType || undefined,
    };
  }
  if (typeof raw.disableResilienceDefaults === "boolean") {
    out.disableResilienceDefaults = raw.disableResilienceDefaults;
  }

  return Object.keys(out).length > 0 ? out : undefined;
}

// The two session controls that only exist on the beta endpoint, read from a
// beta conditionalAccess/policies item. Returns undefined fields (not false)
// when the key is absent, so "beta didn't report it" never reads as "off".
export function mapCaBetaSessionExtras(betaPolicy: any): Pick<CaSessionControls, "tokenProtection" | "continuousAccessEvaluation"> {
  const sc = betaPolicy?.sessionControls;
  if (!sc || typeof sc !== "object") return {};
  const out: Pick<CaSessionControls, "tokenProtection" | "continuousAccessEvaluation"> = {};
  if (sc.secureSignInSession && typeof sc.secureSignInSession === "object") {
    out.tokenProtection = !!sc.secureSignInSession.isEnabled;
  }
  const caeMode = sc.continuousAccessEvaluation?.mode;
  if (caeMode === "disabled" || caeMode === "strictEnforcement" || caeMode === "strictLocation") {
    out.continuousAccessEvaluation = caeMode;
  }
  return out;
}

// Merges beta-only session extras onto already-mapped v1.0 policies by id.
// A policy the beta read didn't return keeps its v1.0 sessionControls as-is.
// A policy the beta read DID return always gets an explicit tokenProtection
// (false when secureSignInSession is absent), so consumers can tell "beta
// confirmed no token protection" (false) from "beta never read" (undefined).
// continuousAccessEvaluation stays undefined when absent: that means the
// default CAE behaviour, which is the correct reading once beta was read.
export function applyCaBetaSessionExtras(
  policies: CAPolicyRule[],
  extrasById: Map<string, Pick<CaSessionControls, "tokenProtection" | "continuousAccessEvaluation">>
): CAPolicyRule[] {
  if (extrasById.size === 0) return policies;
  return policies.map((policy) => {
    const extras = extrasById.get(policy.id);
    if (!extras) return policy;
    return {
      ...policy,
      sessionControls: { ...(policy.sessionControls || {}), ...extras, tokenProtection: extras.tokenProtection ?? false },
    };
  });
}

// identity/conditionalAccess/namedLocations. Discriminated by @odata.type
// (countryNamedLocation / ipNamedLocation, confirmed against Microsoft Learn
// 2026-09-29). Unknown types are dropped rather than guessed at.
export function mapNamedLocation(raw: any): CaNamedLocation | null {
  if (!raw?.id) return null;
  const odataType: string = (raw["@odata.type"] || "").toLowerCase();

  if (odataType.endsWith("countrynamedlocation")) {
    return {
      id: raw.id,
      displayName: raw.displayName || raw.id,
      kind: "country",
      countries: (raw.countriesAndRegions || []).map((c: string) => String(c).toUpperCase()),
      includeUnknownCountries: !!raw.includeUnknownCountriesAndRegions,
      countryLookupMethod: raw.countryLookupMethod === "authenticatorAppGps" ? "authenticatorAppGps" : "clientIpAddress",
    };
  }

  if (odataType.endsWith("ipnamedlocation")) {
    return {
      id: raw.id,
      displayName: raw.displayName || raw.id,
      kind: "ip",
      ipRanges: (raw.ipRanges || []).map((r: any) => r?.cidrAddress).filter((r: unknown): r is string => typeof r === "string"),
      isTrusted: !!raw.isTrusted,
    };
  }

  return null;
}

// Built-in guest user role template ids (authorizationPolicy.guestUserRoleId).
const GUEST_ROLE_LEVELS: Record<string, TenantIdentitySettings["guestAccessLevel"]> = {
  "a0b1b346-4d3e-4e8b-98f8-753987be4970": "sameAsMember",
  "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited",
  "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted",
};

const INVITE_SETTINGS = new Set(["none", "adminsAndGuestInviters", "adminsGuestInvitersAndAllMembers", "everyone"]);

// Only "ManagePermissionGrantsForSelf.*" entries govern end-user consent -
// "ManagePermissionGrantsForOwnedResource.*" entries are group/team owner
// consent, a separate setting that happens to live in the same array.
export function deriveUserConsentMode(assigned: string[]): TenantIdentitySettings["userConsentMode"] {
  const selfPolicies = assigned
    .filter((p) => p.startsWith("ManagePermissionGrantsForSelf."))
    .map((p) => p.slice("ManagePermissionGrantsForSelf.".length));
  if (selfPolicies.length === 0) return "disabled";
  if (selfPolicies.includes("microsoft-user-default-legacy")) return "allApps";
  if (selfPolicies.length === 1 && selfPolicies[0] === "microsoft-user-default-low") return "verifiedPublishersLowRisk";
  if (selfPolicies.length === 1 && selfPolicies[0] === "microsoft-user-default-recommended") return "microsoftRecommended";
  return "custom";
}

// Assembles TenantIdentitySettings from the three independent policy reads.
// Any argument can be undefined (that read failed or wasn't made) - its
// fields stay undefined rather than defaulting to a guess.
export function mapTenantIdentitySettings(
  securityDefaults: any | undefined,
  authorizationPolicy: any | undefined,
  adminConsentRequestPolicy: any | undefined
): TenantIdentitySettings {
  const out: TenantIdentitySettings = {};

  if (securityDefaults && typeof securityDefaults.isEnabled === "boolean") {
    out.securityDefaultsEnabled = securityDefaults.isEnabled;
  }

  if (authorizationPolicy) {
    const assigned = authorizationPolicy.defaultUserRolePermissions?.permissionGrantPoliciesAssigned;
    if (Array.isArray(assigned)) {
      out.userConsentPolicies = assigned;
      out.userConsentMode = deriveUserConsentMode(assigned);
    }
    if (typeof authorizationPolicy.guestUserRoleId === "string") {
      out.guestAccessLevel = GUEST_ROLE_LEVELS[authorizationPolicy.guestUserRoleId.toLowerCase()] || "unknown";
    }
    if (typeof authorizationPolicy.allowInvitesFrom === "string") {
      out.guestInviteSetting = INVITE_SETTINGS.has(authorizationPolicy.allowInvitesFrom)
        ? (authorizationPolicy.allowInvitesFrom as TenantIdentitySettings["guestInviteSetting"])
        : "unknown";
    }
  }

  if (adminConsentRequestPolicy && typeof adminConsentRequestPolicy.isEnabled === "boolean") {
    out.adminConsentWorkflowEnabled = adminConsentRequestPolicy.isEnabled;
  }

  return out;
}
