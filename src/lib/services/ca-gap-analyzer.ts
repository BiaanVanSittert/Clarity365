import { CAPolicyRule, TenantSecuritySnapshot } from "../types";
import { CaEnvironment, CaPolicyTrace, CaSimUser, SignInContext, evaluateSignIn, securityDefaultsPolicies } from "./ca-policy-evaluator";
import { buildCaEnvironment, buildSyntheticSimUser, detectLikelyBreakGlassAccounts, listSimAccounts } from "./ca-sim-context";
import { SituationPersona } from "../data/signin-situation-definitions";

// CA Gap Analysis (ai-context-vault/Optimization/Security Simulations Plan.md,
// Stage 4): a persona x control coverage matrix, a score out of 10, and a
// severity-ranked findings list.
//
// Every user-persona cell is decided by running the SAME engine the Sign-in
// Situations view uses on a representative sign-in, then checking whether an
// applying policy provides the control - so the matrix can never disagree
// with a simulated sign-in. Representative users are synthetic: they match
// "All users", guest and role targeting but never a specific person's or
// group's exclusion, so the matrix answers "does policy cover this persona
// as a whole"; individual exclusions are reported as findings instead.

// ------------------------------------------------------------------ types

export type CaGapPersona = "admins" | "users" | "guests" | "workloadIdentities";
export type CaGapControl =
  | "mfa"
  | "phishingResistant"
  | "managedDevice"
  | "legacyBlocked"
  | "signInRisk"
  | "userRisk"
  | "sessionLimits"
  | "locationRestrictions";

export type CaGapCellState = "enforced" | "reportOnly" | "noPolicy" | "unlicensed" | "notApplicable" | "unknown";

export interface CaGapCell {
  persona: CaGapPersona;
  control: CaGapControl;
  state: CaGapCellState;
  // Policies behind the cell (enforcing, or report-only when that's all there is).
  policies: { id: string; name: string; state: CAPolicyRule["state"] }[];
  note?: string;
}

export type CaGapSeverity = "critical" | "high" | "medium" | "low";

export interface CaGapFinding {
  id: string;
  severity: CaGapSeverity;
  // Short origin label, like the reference screenshot's "Persona coverage" / "Microsoft guidance".
  source: string;
  title: string;
  detail: string;
  policies: string[];
  fix: string;
  docsUrl?: string;
  // When set, the UI offers "Try it in Sign-in Situations" for this persona.
  simulatePersona?: SituationPersona;
}

export interface CaGapAnalysis {
  score: number;
  maxScore: 10;
  enforcedControls: number;
  scoredControls: number;
  matrix: CaGapCell[];
  findings: CaGapFinding[];
  severityCounts: Record<CaGapSeverity, number>;
  policyCounts: { total: number; enabled: number; reportOnly: number; disabled: number };
  // True when some policies were synced before simulation support.
  needsResync: boolean;
}

export const CA_GAP_PERSONAS: { id: CaGapPersona; label: string }[] = [
  { id: "admins", label: "Admins" },
  { id: "users", label: "Users" },
  { id: "guests", label: "Guests" },
  { id: "workloadIdentities", label: "Workload identities" },
];

export const CA_GAP_CONTROLS: { id: CaGapControl; label: string }[] = [
  { id: "mfa", label: "Multifactor authentication" },
  { id: "phishingResistant", label: "Phishing-resistant authentication" },
  { id: "managedDevice", label: "Managed device" },
  { id: "legacyBlocked", label: "Legacy authentication blocked" },
  { id: "signInRisk", label: "Sign-in risk response" },
  { id: "userRisk", label: "User risk response" },
  { id: "sessionLimits", label: "Session limits" },
  { id: "locationRestrictions", label: "Location restrictions" },
];

// Microsoft Learn pages, each verified to exist on 2026-09-30.
export const CA_DOCS = {
  mfaAllUsers: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength",
  adminPhishingResistant: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa",
  guestsMfa: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-guests-mfa-strength",
  deviceRegistration: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-registration",
  securityInfoRegistration: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration",
  emergencyAccess: "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access",
  signInRisk: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in",
  userRisk: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user",
  blockByLocation: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-by-location",
  workloadIdentities: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity",
  legacyAuth: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication",
  deviceCompliance: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance",
  sessionLifetime: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-session-lifetime",
  reportOnly: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only",
  securityDefaults: "https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults",
  externalAuthMethods: "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage",
} as const;

// ------------------------------------------------------ matrix: probes

type PolicyPredicate = (policy: CAPolicyRule, trace: CaPolicyTrace) => boolean;

interface ControlProbe {
  contexts: Partial<SignInContext>[];
  // All contexts must be covered (legacy: both EAS and "other") or any one.
  require: "all" | "any";
  provides: PolicyPredicate;
}

const hasControl = (p: CAPolicyRule, pred: (c: string) => boolean) => (p.grantControls || []).some((c) => pred(c.toLowerCase()));
const blocksOrRequires = (t: CaPolicyTrace) => !!t.grant && t.grant.kind !== "satisfied";

// Representative sign-ins: Office 365 in a browser on Windows at home,
// with a compliant device unless the probe is about devices.
const BASE: Omit<SignInContext, "user"> = {
  target: { kind: "resource", resource: "Office365" },
  clientAppType: "browser",
  platform: "windows",
  device: "compliant",
  location: { country: "__HOME__", ipNamedLocationIds: [] },
  signInRisk: "none",
  userRisk: "none",
  insiderRisk: "none",
};

const PROBES: Record<Exclude<CaGapControl, never>, ControlProbe> = {
  mfa: {
    contexts: [{ device: "unmanaged" }],
    require: "any",
    provides: (p) => hasControl(p, (c) => c === "mfa" || c.startsWith("authenticationstrength:")),
  },
  phishingResistant: {
    contexts: [{ device: "unmanaged" }],
    require: "any",
    provides: (p) => hasControl(p, (c) => c.startsWith("authenticationstrength:") && c.includes("phishing")),
  },
  managedDevice: {
    contexts: [{ device: "unmanaged" }],
    require: "any",
    provides: (p) => hasControl(p, (c) => c === "compliantdevice" || c === "domainjoineddevice"),
  },
  legacyBlocked: {
    contexts: [{ clientAppType: "exchangeActiveSync" }, { clientAppType: "other" }],
    require: "all",
    provides: (p, t) => t.grant?.kind === "block",
  },
  signInRisk: {
    contexts: [{ signInRisk: "high" }],
    require: "any",
    provides: (p, t) => (p.conditions.signInRiskLevels || []).map((l) => l.toLowerCase()).includes("high") && blocksOrRequires(t),
  },
  userRisk: {
    contexts: [{ userRisk: "high" }],
    require: "any",
    provides: (p, t) => (p.conditions.userRiskLevels || []).map((l) => l.toLowerCase()).includes("high") && blocksOrRequires(t),
  },
  sessionLimits: {
    contexts: [{}],
    require: "any",
    provides: (p) =>
      !!p.sessionControls &&
      (!!p.sessionControls.signInFrequency?.isEnabled || p.sessionControls.persistentBrowser?.mode === "never" || !!p.sessionControls.tokenProtection),
  },
  locationRestrictions: {
    // A country almost no tenant allows, and an address that maps to no country.
    contexts: [{ location: { country: "KP", ipNamedLocationIds: [] } }, { location: { country: null, ipNamedLocationIds: [] } }],
    require: "any",
    provides: (p, t) => ((p.conditions.locations?.include || []).length > 0 || (p.conditions.locations?.exclude || []).length > 0) && blocksOrRequires(t),
  },
};

// Cells Microsoft doesn't support, or that don't make sense, for a persona.
const NOT_APPLICABLE: Partial<Record<CaGapPersona, Partial<Record<CaGapControl, string>>>> = {
  guests: {
    phishingResistant: "Phishing-resistant strength for guests depends on cross-tenant MFA trust; not scored.",
    managedDevice: "A guest's device isn't managed by this tenant.",
    signInRisk: "Guest risk is evaluated by the guest's home organisation, not this tenant.",
    userRisk: "Guest risk is evaluated by the guest's home organisation, not this tenant.",
  },
};

function probeUser(persona: Exclude<CaGapPersona, "workloadIdentities">): CaSimUser {
  return buildSyntheticSimUser(persona === "admins" ? "globalAdmin" : persona === "users" ? "user" : "guest");
}

function evaluateUserCell(
  persona: Exclude<CaGapPersona, "workloadIdentities">,
  control: CaGapControl,
  env: CaEnvironment,
  homeCountry: string
): CaGapCell {
  const na = NOT_APPLICABLE[persona]?.[control];
  if (na) return { persona, control, state: "notApplicable", policies: [], note: na };
  if ((control === "signInRisk" || control === "userRisk") && !env.entraP2Licensed) {
    return { persona, control, state: "unlicensed", policies: [], note: "Risk-based policies need Microsoft Entra ID P2." };
  }

  const probe = PROBES[control];
  const byId = new Map([...env.policies, ...securityDefaultsPolicies()].map((p) => [p.id, p]));
  const user = probeUser(persona);

  const perContext = probe.contexts.map((overrides) => {
    const ctx: SignInContext = {
      ...BASE,
      ...overrides,
      user,
      location: overrides.location ?? { country: homeCountry, ipNamedLocationIds: [] },
    };
    const result = evaluateSignIn(ctx, env);
    const matching = (states: CAPolicyRule["state"][], applies: CaPolicyTrace["applies"]) =>
      result.trace.filter((t) => t.source === "policy" && t.applies === applies && states.includes(t.state) && probe.provides(byId.get(t.policyId)!, t));
    // Security defaults count as enforced protection for MFA / legacy.
    const defaults = result.trace.filter((t) => t.source === "securityDefaults" && t.applies === "yes" && probe.provides(byId.get(t.policyId)!, t));
    return {
      enforced: matching(["enabled"], "yes"),
      reportOnly: matching(["enabledForReportingButNotEnforced"], "yes"),
      uncertain: matching(["enabled"], "unknown"),
      defaults,
    };
  });

  const covered = (key: "enforced" | "reportOnly" | "uncertain") =>
    probe.require === "all" ? perContext.every((c) => c[key].length > 0) : perContext.some((c) => c[key].length > 0);
  const collect = (key: "enforced" | "reportOnly" | "uncertain") => {
    const seen = new Map<string, { id: string; name: string; state: CAPolicyRule["state"] }>();
    for (const c of perContext) for (const t of c[key]) seen.set(t.policyId, { id: t.policyId, name: t.policyName, state: t.state });
    return [...seen.values()];
  };

  if (covered("enforced")) return { persona, control, state: "enforced", policies: collect("enforced") };
  if (perContext.some((c) => c.defaults.length > 0) && (probe.require === "any" || perContext.every((c) => c.defaults.length > 0 || c.enforced.length > 0))) {
    return { persona, control, state: "enforced", policies: [], note: "Provided by security defaults." };
  }
  if (covered("uncertain")) return { persona, control, state: "unknown", policies: collect("uncertain"), note: "A policy might provide this but couldn't be confirmed." };
  // Report-only counts only when it would close the gap together with what's enforced.
  const reportOnlyCloses =
    probe.require === "all"
      ? perContext.every((c) => c.enforced.length > 0 || c.reportOnly.length > 0)
      : perContext.some((c) => c.reportOnly.length > 0);
  if (reportOnlyCloses) return { persona, control, state: "reportOnly", policies: collect("reportOnly") };

  // Microsoft recommends phishing-resistant MFA for administrators; for
  // everyone else it's optional, so its absence isn't scored as a gap.
  if (persona === "users" && control === "phishingResistant") {
    return { persona, control, state: "notApplicable", policies: [], note: "Microsoft recommends phishing-resistant MFA for administrators; it's optional for other users." };
  }

  const partial = probe.require === "all" && perContext.some((c) => c.enforced.length > 0);
  return {
    persona,
    control,
    state: "noPolicy",
    policies: partial ? collect("enforced") : [],
    note: partial ? "Only part of legacy authentication is blocked (Exchange ActiveSync or other clients, not both)." : undefined,
  };
}

// Workload identities can't be simulated with a user sign-in; their cells
// come from policies that target service principals directly.
function evaluateWorkloadCell(control: CaGapControl, env: CaEnvironment): CaGapCell {
  const persona: CaGapPersona = "workloadIdentities";
  if (control !== "signInRisk" && control !== "locationRestrictions") {
    return { persona, control, state: "notApplicable", policies: [], note: "Workload identities can't do MFA, use devices or sessions." };
  }
  const relevant = env.policies.filter(
    (p) =>
      p.state !== "disabled" &&
      (p.conditions.clientApplications?.includeServicePrincipals || []).length > 0 &&
      (control === "signInRisk"
        ? (p.conditions.servicePrincipalRiskLevels || []).length > 0
        : (p.conditions.locations?.include || []).length > 0 || (p.conditions.locations?.exclude || []).length > 0)
  );
  const enabled = relevant.filter((p) => p.state === "enabled");
  const list = (ps: CAPolicyRule[]) => ps.map((p) => ({ id: p.id, name: p.name, state: p.state }));
  if (enabled.length > 0) return { persona, control, state: "enforced", policies: list(enabled) };
  if (relevant.length > 0) return { persona, control, state: "reportOnly", policies: list(relevant) };
  return {
    persona,
    control,
    state: "unlicensed",
    policies: [],
    note: "Policies for workload identities need Microsoft Entra Workload ID Premium (licence not detected either way).",
  };
}

// --------------------------------------------------------------- scoring

// Cells that matter most weigh double in the score.
const CRITICAL_CELLS = new Set(["admins:mfa", "admins:phishingResistant", "users:mfa", "admins:legacyBlocked", "users:legacyBlocked", "guests:mfa"]);

function scoreMatrix(cells: CaGapCell[]): { score: number; enforced: number; scored: number } {
  // Not-applicable and unlicensed cells are left out; workload identities
  // are shown but not scored (their licence can't be detected).
  const scoredCells = cells.filter((c) => c.persona !== "workloadIdentities" && c.state !== "notApplicable" && c.state !== "unlicensed");
  let weightTotal = 0;
  let weightEnforced = 0;
  for (const c of scoredCells) {
    const w = CRITICAL_CELLS.has(`${c.persona}:${c.control}`) ? 2 : 1;
    weightTotal += w;
    if (c.state === "enforced") weightEnforced += w;
  }
  return {
    score: weightTotal === 0 ? 0 : Math.round((10 * weightEnforced) / weightTotal),
    enforced: scoredCells.filter((c) => c.state === "enforced").length,
    scored: scoredCells.length,
  };
}

// -------------------------------------------------------------- findings

const PERSONA_TO_SIM: Partial<Record<CaGapPersona, SituationPersona>> = { admins: "globalAdmin", users: "user", guests: "guest" };

const CELL_SEVERITY: Record<string, CaGapSeverity> = {
  "admins:mfa": "critical",
  "users:mfa": "critical",
  "admins:legacyBlocked": "critical",
  "users:legacyBlocked": "high",
  "guests:legacyBlocked": "high",
  "guests:mfa": "high",
  "admins:phishingResistant": "high",
  "admins:managedDevice": "high",
  "users:managedDevice": "medium",
  "admins:signInRisk": "medium",
  "users:signInRisk": "medium",
  "admins:userRisk": "medium",
  "users:userRisk": "medium",
  "admins:sessionLimits": "medium",
  "users:sessionLimits": "low",
  "guests:sessionLimits": "low",
  "admins:locationRestrictions": "medium",
  "users:locationRestrictions": "medium",
  "guests:locationRestrictions": "low",
};

const CELL_DOCS: Record<CaGapControl, string> = {
  mfa: CA_DOCS.mfaAllUsers,
  phishingResistant: CA_DOCS.adminPhishingResistant,
  managedDevice: CA_DOCS.deviceCompliance,
  legacyBlocked: CA_DOCS.legacyAuth,
  signInRisk: CA_DOCS.signInRisk,
  userRisk: CA_DOCS.userRisk,
  sessionLimits: CA_DOCS.sessionLifetime,
  locationRestrictions: CA_DOCS.blockByLocation,
};

const CELL_FIX: Record<CaGapControl, string> = {
  mfa: "Extend a policy that already applies to this persona with multifactor authentication, or add a dedicated one.",
  phishingResistant: "Require the built-in phishing-resistant MFA authentication strength for administrator roles (after admins have registered passkeys or FIDO2 keys).",
  managedDevice: "Require a compliant or Microsoft Entra hybrid joined device, or add this persona to a policy that already does.",
  legacyBlocked: "Block the Exchange ActiveSync and Other clients client app types for all users.",
  signInRisk: "Require MFA (or block) when sign-in risk is medium or high.",
  userRisk: "Require risk remediation (or a secure password change) when user risk is high.",
  sessionLimits: "Set a sign-in frequency and disable persistent browser sessions, at least for administrators.",
  locationRestrictions: "Block sign-ins from countries you don't operate in, excluding only the countries you need.",
};

function lower1(s: string): string {
  return s.charAt(0).toLowerCase() + s.slice(1);
}

function coverageFindings(cells: CaGapCell[]): CaGapFinding[] {
  const out: CaGapFinding[] = [];
  for (const c of cells) {
    if (c.persona === "workloadIdentities") continue;
    const key = `${c.persona}:${c.control}`;
    const severity = CELL_SEVERITY[key];
    if (!severity) continue;
    const personaLabel = CA_GAP_PERSONAS.find((p) => p.id === c.persona)!.label;
    const controlLabel = CA_GAP_CONTROLS.find((x) => x.id === c.control)!.label;
    if (c.state === "noPolicy") {
      out.push({
        id: `coverage:${key}`,
        severity,
        source: "Persona coverage",
        title: `${personaLabel} have no enforced policy for "${controlLabel}"`,
        detail: `None of the enforced policies that apply to ${personaLabel.toLowerCase()} provide this control.${c.note ? ` ${c.note}` : ""}`,
        policies: c.policies.map((p) => p.name),
        fix: CELL_FIX[c.control],
        docsUrl: CELL_DOCS[c.control],
        simulatePersona: PERSONA_TO_SIM[c.persona],
      });
    } else if (c.state === "reportOnly") {
      out.push({
        id: `reportonly:${key}`,
        severity: severity === "critical" ? "high" : severity === "high" ? "medium" : "low",
        source: "Persona coverage",
        title: `${personaLabel}: "${controlLabel}" is only in report-only mode`,
        detail: `A policy would provide this control for ${personaLabel.toLowerCase()}, but it's in report-only mode, so nothing is enforced yet.`,
        policies: c.policies.map((p) => p.name),
        fix: "Review the policy's report-only results in the sign-in logs, then switch it on.",
        docsUrl: CA_DOCS.reportOnly,
        simulatePersona: PERSONA_TO_SIM[c.persona],
      });
    }
  }
  return out;
}

// Policies that block or restrict sign-in for everyone (or every admin) and
// exclude nobody - one misconfiguration away from locking the tenant out.
function lockoutFindings(policies: CAPolicyRule[]): CaGapFinding[] {
  const restricting = policies.filter((p) => {
    if (p.state !== "enabled") return false;
    const u = p.conditions.users;
    const broad = (u.include || []).some((e) => e.toLowerCase() === "all") || (u.includeRoles || []).length > 0 || (u.include || []).includes("AllAdmins");
    const excludesAnyone = (u.exclude || []).some((e) => e.toLowerCase() !== "guestsorexternalusers") || (u.excludeGroupIds || []).length > 0;
    const appliesToEverything = (p.conditions.applications.include || []).some((a) => a.toLowerCase() === "all");
    const restricts = hasControl(p, (c) => c === "block" || c === "compliantdevice" || c === "domainjoineddevice" || c.startsWith("authenticationstrength:") || c === "mfa");
    const narrowed = (p.conditions.clientAppTypes || []).some((t) => ["exchangeactivesync", "other", "eassupported"].includes(t.toLowerCase())) || (p.conditions.authenticationFlows || []).length > 0 || (p.conditions.signInRiskLevels || []).length > 0 || (p.conditions.userRiskLevels || []).length > 0 || (p.conditions.insiderRiskLevels || []).length > 0;
    return broad && !excludesAnyone && appliesToEverything && restricts && !narrowed;
  });
  if (restricting.length === 0) return [];
  const blocks = restricting.some((p) => hasControl(p, (c) => c === "block"));
  return [
    {
      id: "lockout",
      severity: blocks ? "critical" : "high",
      source: "Emergency access",
      title: "Enforced policies with no emergency-access exclusion",
      detail: `${restricting.length} enforced ${restricting.length === 1 ? "policy blocks or restricts" : "policies block or restrict"} sign-in for all users or all admins without excluding any account. If a control can't be satisfied (an MFA outage, a misconfiguration), nobody - including every administrator - can sign in to fix it.`,
      policies: restricting.map((p) => p.name),
      fix: "Create two cloud-only emergency-access (break-glass) accounts with phishing-resistant credentials, put them in a dedicated group, exclude that group from these policies, and alert on every sign-in by them.",
      docsUrl: CA_DOCS.emergencyAccess,
    },
  ];
}

function exclusionFindings(snapshot: TenantSecuritySnapshot): CaGapFinding[] {
  const out: CaGapFinding[] = [];
  const breakGlass = detectLikelyBreakGlassAccounts(snapshot);
  if (breakGlass.length > 0) {
    out.push({
      id: "breakglass:confirm",
      severity: "low",
      source: "Emergency access",
      title: `Confirm ${breakGlass.length === 1 ? "this looks like an emergency-access account" : `${breakGlass.length} accounts look like emergency-access accounts`}`,
      detail: `${breakGlass
        .map((b) => `${b.displayName || b.userPrincipalName || b.ref} (${b.reasons.join("; ")})`)
        .join("; ")}. Excluding break-glass accounts is correct, but only if they really are, use phishing-resistant credentials, and every sign-in raises an alert.`,
      policies: [],
      fix: "Confirm each account is a dedicated emergency-access account, not a person's daily account, and set up sign-in alerting for it.",
      docsUrl: CA_DOCS.emergencyAccess,
    });
  }

  const lists = listSimAccounts(snapshot);
  const excluded = [...lists.globalAdmins, ...lists.otherAdmins, ...lists.standardUsers, ...lists.guests].filter((a) => a.excludedFrom && !a.breakGlassReasons);
  if (excluded.length > 0) {
    out.push({
      id: "exclusions:individual",
      severity: excluded.some((a) => a.roles && a.roles.length > 0) ? "high" : "medium",
      source: "Exclusions",
      title: `${excluded.length} account${excluded.length === 1 ? " is" : "s are"} individually excluded from policies`,
      detail: excluded
        .slice(0, 8)
        .map((a) => `${a.displayName} (${a.userPrincipalName}): ${a.excludedFrom!.join(", ")}`)
        .concat(excluded.length > 8 ? [`and ${excluded.length - 8} more`] : [])
        .join("; "),
      policies: [...new Set(excluded.flatMap((a) => a.excludedFrom!))],
      fix: "Remove each exclusion that's no longer needed. For service accounts, prefer a managed identity or a workload-identity policy over excluding the account.",
      docsUrl: CA_DOCS.mfaAllUsers,
      simulatePersona: excluded.some((a) => lists.standardUsers.includes(a)) ? "user" : undefined,
    });
  }
  return out;
}

function registrationFindings(env: CaEnvironment): CaGapFinding[] {
  const out: CaGapFinding[] = [];
  const enabled = env.policies.filter((p) => p.state === "enabled");
  const coversAction = (action: string) => enabled.some((p) => (p.conditions.applications.userActions || []).includes(action));

  const locationBlocks = enabled.filter((p) => ((p.conditions.locations?.include || []).length > 0 || (p.conditions.locations?.exclude || []).length > 0) && hasControl(p, (c) => c === "block"));
  if (locationBlocks.length > 0 && !coversAction("urn:user:registerdevice")) {
    out.push({
      id: "registration:device",
      severity: "medium",
      source: "Device registration",
      title: "Device registration is not covered by the conditions of these policies",
      detail:
        "These policies block access based on network location, but the device registration service ignores location conditions. New devices can still be registered from an untrusted network, and no enforced policy requires MFA when a device is registered. (Clarity365 can't read the tenant-wide \"Require MFA to register or join devices\" device setting, which may already cover this.)",
      policies: locationBlocks.map((p) => p.name),
      fix: "Require multifactor authentication for registering or joining devices through a dedicated \"Register or join devices\" user-action policy, and set the device setting to No so that policy is enforced.",
      docsUrl: CA_DOCS.deviceRegistration,
    });
  }
  if (!coversAction("urn:user:registersecurityinfo")) {
    out.push({
      id: "registration:securityinfo",
      severity: "medium",
      source: "Registration",
      title: "Security info registration isn't protected",
      detail: "No enforced policy targets the \"Register security information\" user action. Someone holding only a password can register their own MFA method - often the first step after an account is compromised.",
      policies: [],
      fix: "Require MFA (or a trusted location) to register security info, and issue Temporary Access Passes for new users.",
      docsUrl: CA_DOCS.securityInfoRegistration,
    });
  }
  return out;
}

function hygieneFindings(env: CaEnvironment, snapshot: TenantSecuritySnapshot, now: Date): CaGapFinding[] {
  const out: CaGapFinding[] = [];
  const policies = env.policies;

  // Risk remediation paired with an authentication strength can't be
  // satisfied by an external MFA provider (Microsoft Learn warning).
  const riskWithStrength = policies.filter(
    (p) => p.state !== "disabled" && (p.conditions.userRiskLevels || []).length > 0 && hasControl(p, (c) => c.startsWith("authenticationstrength:"))
  );
  if (riskWithStrength.length > 0) {
    out.push({
      id: "guidance:external-provider",
      severity: "high",
      source: "Microsoft guidance",
      title: "Risk remediation cannot be completed by users of an external provider",
      detail:
        "These policies ask risky users to remediate through an authentication strength. Authentication strengths can't accept external authentication providers such as Duo, Okta or Ping, so people who rely on one stay blocked once flagged. Whether this tenant uses an external authentication provider couldn't be verified, so this is shown as a precaution.",
      policies: riskWithStrength.map((p) => p.name),
      fix: "Add a companion risk policy for the users of the external provider that requires plain multifactor authentication together with risk remediation, and keep the stronger requirement for everyone else.",
      docsUrl: CA_DOCS.externalAuthMethods,
    });
  }

  const reportOnlyOld = policies.filter((p) => {
    if (p.state !== "enabledForReportingButNotEnforced") return false;
    const modified = Date.parse(p.modifiedDateTime);
    return Number.isFinite(modified) && now.getTime() - modified > 30 * 24 * 3600 * 1000;
  });
  if (reportOnlyOld.length > 0) {
    out.push({
      id: "hygiene:report-only-old",
      severity: "low",
      source: "Policy hygiene",
      title: `${reportOnlyOld.length} ${reportOnlyOld.length === 1 ? "policy has" : "policies have"} been in report-only mode for over 30 days`,
      detail: "Report-only is meant for a short trial. Long-running report-only policies protect nothing and are often forgotten.",
      policies: reportOnlyOld.map((p) => p.name),
      fix: "Review each policy's report-only results in the sign-in logs, then switch it on or delete it.",
      docsUrl: CA_DOCS.reportOnly,
    });
  }

  const disabled = policies.filter((p) => p.state === "disabled");
  if (disabled.length > 0) {
    out.push({
      id: "hygiene:disabled",
      severity: "low",
      source: "Policy hygiene",
      title: `${disabled.length} disabled ${disabled.length === 1 ? "policy" : "policies"}`,
      detail: "Disabled policies clutter the policy list and can be switched back on by mistake.",
      policies: disabled.map((p) => p.name),
      fix: "Delete policies that are no longer needed.",
    });
  }

  if (!env.entraP2Licensed) {
    const riskPolicies = policies.filter((p) => p.state !== "disabled" && ((p.conditions.signInRiskLevels || []).length > 0 || (p.conditions.userRiskLevels || []).length > 0));
    if (riskPolicies.length > 0) {
      out.push({
        id: "licence:risk-without-p2",
        severity: "medium",
        source: "Licensing",
        title: "Risk-based policies without Microsoft Entra ID P2",
        detail: "These policies use sign-in or user risk, but the tenant doesn't have Entra ID P2, so they never evaluate.",
        policies: riskPolicies.map((p) => p.name),
        fix: "License Entra ID P2 (Microsoft 365 E5 or the P2 add-on) for the users these policies cover, or remove the policies.",
        docsUrl: CA_DOCS.signInRisk,
      });
    }
  }

  const locations = env.namedLocations || [];
  const locationIds = new Set(locations.map((l) => l.id));
  if (env.namedLocations) {
    const dangling = policies.filter((p) =>
      [...(p.conditions.locations?.include || []), ...(p.conditions.locations?.exclude || [])].some((r) => r !== "All" && r !== "AllTrusted" && !locationIds.has(r))
    );
    if (dangling.length > 0) {
      out.push({
        id: "hygiene:dangling-location",
        severity: "medium",
        source: "Policy hygiene",
        title: "Policies reference named locations that no longer exist",
        detail: "A deleted named location silently changes what a location condition covers.",
        policies: dangling.map((p) => p.name),
        fix: "Edit each policy's location condition to use existing named locations.",
        docsUrl: CA_DOCS.blockByLocation,
      });
    }
  }

  const broadTrusted = locations.filter((l) => l.kind === "ip" && l.isTrusted && (l.ipRanges || []).some((r) => {
    const [addr, prefix] = r.split("/");
    const bits = Number(prefix);
    return addr.includes(":") ? bits < 48 : bits < 16;
  }));
  if (broadTrusted.length > 0) {
    out.push({
      id: "hygiene:broad-trusted",
      severity: "medium",
      source: "Named locations",
      title: "Trusted named locations with very large IP ranges",
      detail: `${broadTrusted.map((l) => l.displayName).join(", ")}: trusting ranges this large (bigger than a /16) can trust far more of the internet than your offices.`,
      policies: [],
      fix: "Limit trusted locations to your offices' actual egress addresses.",
      docsUrl: CA_DOCS.blockByLocation,
    });
  }

  if (snapshot.identitySettings?.securityDefaultsEnabled) {
    out.push({
      id: "securitydefaults",
      severity: "high",
      source: "Tenant configuration",
      title: "Security defaults are on, so Conditional Access isn't in use",
      detail: "Security defaults give a fixed baseline (MFA registration and prompts, legacy authentication blocked) but no location, device, risk or session controls.",
      policies: [],
      fix: "If the tenant has Entra ID P1, replace security defaults with Conditional Access policies (CA01-CA10), then turn security defaults off.",
      docsUrl: CA_DOCS.securityDefaults,
    });
  }

  const deviceFilterPolicies = policies.filter((p) => p.state !== "disabled" && p.conditions.deviceFilter);
  if (deviceFilterPolicies.length > 0) {
    out.push({
      id: "info:device-filters",
      severity: "low",
      source: "Simulation limits",
      title: "Policies with device filters can't be fully simulated",
      detail: "Device filter rules are their own expression language; results involving these policies show as \"can't confirm\".",
      policies: deviceFilterPolicies.map((p) => p.name),
      fix: "No action needed - check these policies' behaviour in Microsoft's What If tool if a result matters.",
    });
  }

  return out;
}

// -------------------------------------------------------------- analysis

const SEVERITY_ORDER: CaGapSeverity[] = ["critical", "high", "medium", "low"];

export function analyzeCaGaps(snapshot: TenantSecuritySnapshot, now: Date = new Date(), homeCountry: string = "US"): CaGapAnalysis {
  const env = buildCaEnvironment(snapshot);

  const matrix: CaGapCell[] = [];
  for (const persona of CA_GAP_PERSONAS) {
    for (const control of CA_GAP_CONTROLS) {
      matrix.push(
        persona.id === "workloadIdentities" ? evaluateWorkloadCell(control.id, env) : evaluateUserCell(persona.id, control.id, env, homeCountry)
      );
    }
  }

  const { score, enforced, scored } = scoreMatrix(matrix);

  const findings = [
    ...lockoutFindings(env.policies),
    ...coverageFindings(matrix),
    ...exclusionFindings(snapshot),
    ...registrationFindings(env),
    ...hygieneFindings(env, snapshot, now),
  ].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  const severityCounts: Record<CaGapSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) severityCounts[f.severity] += 1;

  const policies = env.policies;
  return {
    score,
    maxScore: 10,
    enforcedControls: enforced,
    scoredControls: scored,
    matrix,
    findings,
    severityCounts,
    policyCounts: {
      total: policies.length,
      enabled: policies.filter((p) => p.state === "enabled").length,
      reportOnly: policies.filter((p) => p.state === "enabledForReportingButNotEnforced").length,
      disabled: policies.filter((p) => p.state === "disabled").length,
    },
    needsResync: (env.incompletePolicyIds || []).length > 0,
  };
}
