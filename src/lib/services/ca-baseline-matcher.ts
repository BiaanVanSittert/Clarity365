// Matches and validates a live Microsoft Graph or snapshot Conditional Access policy
// against Clarity365's CA01-CA10 baseline standards by inspecting its actual conditions
// and grantControls - ensuring policies match required properties before being marked active.

const AZURE_MANAGEMENT_APP_ID = "797f3427-79cd-4827-8132-47d473d450e4";
const LEGACY_CLIENT_APP_TYPES = new Set(["exchangeActiveSync", "otherClients"]);

export interface RawGraphCaPolicy {
  name?: string;
  displayName?: string;
  baselineCode?: string | null;
  state?: "enabled" | "disabled" | "enabledForReportingButNotEnforced";
  conditions?: {
    users?: { includeUsers?: string[]; includeRoles?: string[]; include?: string[]; exclude?: string[] };
    applications?: { includeApplications?: string[]; include?: string[]; exclude?: string[] };
    clientAppTypes?: string[];
    locations?: { includeLocations?: string[]; excludeLocations?: string[]; include?: string[]; exclude?: string[] };
    platforms?: { includePlatforms?: string[]; include?: string[]; exclude?: string[] };
    userRiskLevels?: string[];
    signInRiskLevels?: string[];
  };
  grantControls?: {
    builtInControls?: string[];
    authenticationStrength?: unknown;
  } | string[];
}

export function controlsInclude(policy: RawGraphCaPolicy, control: string): boolean {
  if (!policy.grantControls) return false;
  if (Array.isArray(policy.grantControls)) {
    return policy.grantControls.some((c) => c.toLowerCase() === control.toLowerCase() || c.toLowerCase().includes(control.toLowerCase()));
  }
  return Boolean(policy.grantControls.builtInControls?.includes(control));
}

export function targetsAdminRoles(policy: RawGraphCaPolicy): boolean {
  const users = policy.conditions?.users;
  if (!users) return false;
  if (users.includeRoles && users.includeRoles.length > 0) return true;
  if (users.include && Array.isArray(users.include)) {
    return users.include.some(
      (u) =>
        u.toLowerCase().includes("admin") ||
        u.toLowerCase().includes("directoryrole") ||
        u === "AllAdmins"
    );
  }
  return false;
}

export function targetsGuests(policy: RawGraphCaPolicy): boolean {
  const users = policy.conditions?.users;
  if (!users) return false;
  if (users.includeUsers?.includes("GuestsOrExternalUsers")) return true;
  if (users.include?.includes("GuestsOrExternalUsers") || users.include?.includes("Guests")) return true;
  return false;
}

export function targetsAllUsers(policy: RawGraphCaPolicy): boolean {
  const users = policy.conditions?.users;
  if (!users) return false;
  if (users.includeUsers?.includes("All")) return true;
  if (users.include?.includes("All")) return true;
  return false;
}

export function targetsAzureManagement(policy: RawGraphCaPolicy): boolean {
  const apps = policy.conditions?.applications;
  if (!apps) return false;
  if (apps.includeApplications?.includes(AZURE_MANAGEMENT_APP_ID)) return true;
  if (apps.include?.includes(AZURE_MANAGEMENT_APP_ID) || apps.include?.some((a) => a.toLowerCase().includes("azure management"))) return true;
  return false;
}

export function hasLocations(policy: RawGraphCaPolicy): boolean {
  const loc = policy.conditions?.locations;
  if (!loc) return false;
  const inc = loc.includeLocations || loc.include || [];
  const exc = loc.excludeLocations || loc.exclude || [];
  return inc.length > 0 || exc.length > 0;
}

export function hasAuthStrengthOrSession(policy: RawGraphCaPolicy): boolean {
  if (!policy.grantControls) return false;
  if (Array.isArray(policy.grantControls)) {
    return policy.grantControls.some(
      (c) =>
        c.toLowerCase().includes("authenticationstrength") ||
        c.toLowerCase().includes("sessioncontrols") ||
        c.toLowerCase().includes("signinfrequency") ||
        c.toLowerCase().includes("cae")
    );
  }
  return Boolean(policy.grantControls.authenticationStrength);
}

// Clarity365's naming convention for a baseline policy: "CA0X: <description>"
// (see tenant-store.ts's deployBaselinePolicy, and the PowerShell scripts in
// baseline-definitions.ts, which both generate/look up policies this way).
export function policyNameMatchesCode(name: string | undefined, code: string): boolean {
  if (!name) return false;
  const upperName = name.toUpperCase();
  const upperCode = code.toUpperCase();
  return upperName.startsWith(`${upperCode}:`) || upperName.startsWith(`${upperCode} `);
}

/**
 * Matches a policy structurally to one of the CA01-CA10 baseline standards based on its conditions and grantControls.
 */
export function matchCaBaselineCode(policy: RawGraphCaPolicy): string | null {
  const hasMfa = controlsInclude(policy, "mfa");
  const hasBlock = controlsInclude(policy, "block");

  // CA10: phishing-resistant MFA / CAE for admins - admin-role-scoped + authentication strength / session controls
  if (hasAuthStrengthOrSession(policy) && (targetsAdminRoles(policy) || targetsAllUsers(policy))) {
    return "CA10";
  }

  // CA07: risk remediation - user risk level + BOTH mfa and passwordChange (AND)
  const userRiskLevels = policy.conditions?.userRiskLevels || [];
  if (userRiskLevels.length > 0 && hasMfa && controlsInclude(policy, "passwordChange")) {
    return "CA07";
  }

  // CA06: MFA for risky sign-ins - sign-in risk level condition present
  const signInRiskLevels = policy.conditions?.signInRiskLevels || [];
  if (signInRiskLevels.length > 0 && hasMfa) {
    return "CA06";
  }

  // CA05: MFA for Azure management - scoped to the Azure Management application ID
  if (targetsAzureManagement(policy) && hasMfa) {
    return "CA05";
  }

  // CA09: compliant/domain-joined device requirement, or the BYOD-equivalent
  // approved-app-with-app-protection-policy requirement - validateCaPolicyCompliance's
  // own CA09 check already accepted all four controls; this branch previously only
  // recognized two of them, so a genuine appProtectionPolicy-based CA09 policy could
  // never satisfy `matched === "CA09"` here even though it passed that other check.
  if (
    controlsInclude(policy, "compliantDevice") ||
    controlsInclude(policy, "domainJoinedDevice") ||
    controlsInclude(policy, "appProtectionPolicy") ||
    controlsInclude(policy, "approvedApplication")
  ) {
    return "CA09";
  }

  // CA03: MFA for admins - admin-role-scoped, plain "mfa" control
  if (targetsAdminRoles(policy) && hasMfa) {
    return "CA03";
  }

  // CA04: MFA for guests
  if (targetsGuests(policy) && hasMfa) {
    return "CA04";
  }

  // CA08: block untrusted locations
  if (hasBlock && hasLocations(policy)) {
    return "CA08";
  }

  // CA01: block legacy authentication client app types
  const clientAppTypes = policy.conditions?.clientAppTypes || [];
  if (hasBlock && clientAppTypes.some((t) => LEGACY_CLIENT_APP_TYPES.has(t))) {
    return "CA01";
  }

  // CA02: MFA for all users - broadest match, evaluated last
  if (hasMfa && targetsAllUsers(policy)) {
    return "CA02";
  }

  return null;
}

/**
 * The naming-aware entry point for classifying a live tenant policy against a
 * baseline code. matchCaBaselineCode() alone only checks structural shape
 * (conditions/grantControls) - that's by design (a misleading name shouldn't
 * make a badly-configured policy look compliant), but it also means any
 * unrelated tenant policy that happens to overlap a baseline's settings gets
 * reported as that baseline's deployed policy (e.g. a policy literally named
 * "mod" that requires MFA on risky sign-ins was being reported as CA06). A
 * policy is only classified as CA0X here if it's BOTH structurally a match
 * AND named per the "CA0X: <description>" convention - use this (not
 * matchCaBaselineCode directly) anywhere a policy is being attributed to a
 * specific baseline for reporting/deployment-status purposes.
 */
export function classifyPolicyBaselineCode(policy: RawGraphCaPolicy): string | null {
  const structuralMatch = matchCaBaselineCode(policy);
  if (!structuralMatch) return null;
  return policyNameMatchesCode(policy.displayName || policy.name, structuralMatch) ? structuralMatch : null;
}

/**
 * Validates whether a policy named/assigned to a specific baseline code actually meets all required properties.
 */
export function validateCaPolicyCompliance(
  policy: RawGraphCaPolicy,
  expectedCode: string
): { isValid: boolean; matchedCode: string | null; missingProperties?: string[] } {
  const matched = matchCaBaselineCode(policy);
  const codeUpper = expectedCode.toUpperCase();
  const missing: string[] = [];

  if (!policyNameMatchesCode(policy.displayName || policy.name, codeUpper)) {
    missing.push(`Policy name must start with "${codeUpper}:"`);
  }

  if (codeUpper === "CA01") {
    if (!controlsInclude(policy, "block")) missing.push("Grant control 'block'");
    const types = policy.conditions?.clientAppTypes || [];
    if (!types.some((t) => LEGACY_CLIENT_APP_TYPES.has(t))) {
      missing.push("Client app types 'exchangeActiveSync' / 'otherClients'");
    }
  } else if (codeUpper === "CA02") {
    if (!controlsInclude(policy, "mfa")) missing.push("Grant control 'mfa'");
    if (!targetsAllUsers(policy)) missing.push("Target scope 'All users'");
  } else if (codeUpper === "CA03") {
    if (!controlsInclude(policy, "mfa")) missing.push("Grant control 'mfa'");
    if (!targetsAdminRoles(policy)) missing.push("Target scope 'Directory Administrator roles'");
  } else if (codeUpper === "CA04") {
    if (!controlsInclude(policy, "mfa") && !controlsInclude(policy, "block")) missing.push("Grant control 'mfa' or 'block'");
  } else if (codeUpper === "CA05") {
    if (!controlsInclude(policy, "mfa")) missing.push("Grant control 'mfa'");
    if (!targetsAzureManagement(policy)) missing.push("Application scope 'Microsoft Azure Management' (797f3427-79cd-4827-8132-47d473d450e4)");
  } else if (codeUpper === "CA06") {
    if (!controlsInclude(policy, "mfa")) missing.push("Grant control 'mfa'");
    const risks = policy.conditions?.signInRiskLevels || [];
    if (risks.length === 0) missing.push("Condition 'Sign-in Risk: medium/high'");
  } else if (codeUpper === "CA07") {
    if (!controlsInclude(policy, "mfa")) missing.push("Grant control 'mfa'");
    if (!controlsInclude(policy, "passwordChange")) missing.push("Grant control 'passwordChange'");
    const userRisks = policy.conditions?.userRiskLevels || [];
    if (userRisks.length === 0) missing.push("Condition 'User Risk: high'");
  } else if (codeUpper === "CA08") {
    if (!controlsInclude(policy, "block")) missing.push("Grant control 'block'");
    if (!hasLocations(policy)) missing.push("Condition 'Locations (untrusted)'");
  } else if (codeUpper === "CA09") {
    if (
      !controlsInclude(policy, "compliantDevice") &&
      !controlsInclude(policy, "domainJoinedDevice") &&
      !controlsInclude(policy, "appProtectionPolicy") &&
      !controlsInclude(policy, "approvedApplication")
    ) {
      missing.push("Grant control 'compliantDevice', 'domainJoinedDevice', or 'appProtectionPolicy'");
    }
  } else if (codeUpper === "CA10") {
    if (!hasAuthStrengthOrSession(policy)) {
      missing.push("Authentication strength 'PhishingResistantMFA' or Session frequency controls");
    }
  }

  const isValid = matched === codeUpper && missing.length === 0;
  return { isValid, matchedCode: matched, missingProperties: missing.length > 0 ? missing : undefined };
}

// Percentage of the CA01-CA10 baseline standards that have at least one deployed
// policy matching them.
export function computeBaselineCoveragePercent(deployedCount: number, totalCount: number): number {
  if (totalCount <= 0) return 0;
  return Math.round((deployedCount / totalCount) * 100);
}
