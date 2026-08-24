// Matches a live Microsoft Graph Conditional Access policy against Clarity365's
// CA01-CA10 baseline standards by inspecting its actual conditions/grantControls —
// never the display name. A customer can name a policy anything; only its structure
// (who it targets, what it requires) tells you what it actually does. Mirrors the
// shapes graph-client.ts's buildGraphCaPolicyPayload deploys for each code.
//
// Ordered most-specific-first: several codes share a signal (CA03/CA10 both target
// admin roles; CA02/CA04 both just require MFA), so the more distinctive match must
// be checked before the broader one steals it.

const AZURE_MANAGEMENT_APP_ID = "797f3427-79cd-4827-8132-47d473d450e4";
const LEGACY_CLIENT_APP_TYPES = new Set(["exchangeActiveSync", "otherClients"]);

export interface RawGraphCaPolicy {
  conditions?: {
    users?: { includeUsers?: string[]; includeRoles?: string[] };
    applications?: { includeApplications?: string[] };
    clientAppTypes?: string[];
    locations?: { includeLocations?: string[]; excludeLocations?: string[] };
    platforms?: { includePlatforms?: string[] };
    userRiskLevels?: string[];
    signInRiskLevels?: string[];
  };
  grantControls?: {
    builtInControls?: string[];
    authenticationStrength?: unknown;
  };
}

function controlsInclude(policy: RawGraphCaPolicy, control: string): boolean {
  return !!policy.grantControls?.builtInControls?.includes(control);
}

function targetsAdminRoles(policy: RawGraphCaPolicy): boolean {
  return !!policy.conditions?.users?.includeRoles?.length;
}

function targetsGuests(policy: RawGraphCaPolicy): boolean {
  return !!policy.conditions?.users?.includeUsers?.includes("GuestsOrExternalUsers");
}

function targetsAllUsers(policy: RawGraphCaPolicy): boolean {
  return !!policy.conditions?.users?.includeUsers?.includes("All");
}

export function matchCaBaselineCode(policy: RawGraphCaPolicy): string | null {
  const hasMfa = controlsInclude(policy, "mfa");
  const hasBlock = controlsInclude(policy, "block");

  // CA10: phishing-resistant MFA for admins — admin-role-scoped + an authentication
  // strength grant control (not plain "mfa"). Must be checked before CA03.
  if (policy.grantControls?.authenticationStrength && targetsAdminRoles(policy)) {
    return "CA10";
  }

  // CA07: risk remediation — user risk level + BOTH mfa and passwordChange (AND).
  const userRiskLevels = policy.conditions?.userRiskLevels || [];
  if (userRiskLevels.length > 0 && hasMfa && controlsInclude(policy, "passwordChange")) {
    return "CA07";
  }

  // CA06: MFA for risky sign-ins — sign-in risk level condition present.
  const signInRiskLevels = policy.conditions?.signInRiskLevels || [];
  if (signInRiskLevels.length > 0 && hasMfa) {
    return "CA06";
  }

  // CA05: MFA for Azure management — scoped to the well-known first-party Azure
  // Management application ID (a stable Microsoft GUID, not something a customer
  // could name their way into matching by accident).
  const includeApps = policy.conditions?.applications?.includeApplications || [];
  if (includeApps.includes(AZURE_MANAGEMENT_APP_ID) && hasMfa) {
    return "CA05";
  }

  // CA09: compliant/domain-joined device requirement.
  if (controlsInclude(policy, "compliantDevice") || controlsInclude(policy, "domainJoinedDevice")) {
    return "CA09";
  }

  // CA03: MFA for admins — admin-role-scoped, plain "mfa" control (CA10 already
  // claimed the authentication-strength variant above).
  if (targetsAdminRoles(policy) && hasMfa) {
    return "CA03";
  }

  // CA04: MFA for guests.
  if (targetsGuests(policy) && hasMfa) {
    return "CA04";
  }

  // CA08: block untrusted locations.
  const locations = policy.conditions?.locations;
  if (hasBlock && locations && ((locations.includeLocations?.length ?? 0) > 0 || (locations.excludeLocations?.length ?? 0) > 0)) {
    return "CA08";
  }

  // CA01: block legacy authentication client app types.
  const clientAppTypes = policy.conditions?.clientAppTypes || [];
  if (hasBlock && clientAppTypes.some((t) => LEGACY_CLIENT_APP_TYPES.has(t))) {
    return "CA01";
  }

  // CA02: MFA for all users — broadest match, evaluated last.
  if (hasMfa && targetsAllUsers(policy)) {
    return "CA02";
  }

  return null;
}
