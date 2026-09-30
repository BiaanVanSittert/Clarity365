import { CAPolicyRule, CaNamedLocation, TenantGroup } from "../types";
import { resolveCaRoleReference, DIRECTORY_ROLE_TEMPLATES } from "../utils/directory-role-templates";

// The Conditional Access "What If" engine behind every Security Simulations
// view (ai-context-vault/Optimization/Security Simulations Plan.md, Stage 2).
// Pure: given one user, one sign-in context and a tenant's CA policies, it
// says which policies apply and what the combined outcome is - and, for
// every policy, why it did or didn't apply. Nothing else in the app should
// re-derive "does this policy apply to this sign-in" inline; that is the
// duplicated-logic bug class in Optimization Plan item 7.
//
// Handles both CA identifier dialects found in snapshots: live Graph ids
// (GUIDs, "All", "GuestsOrExternalUsers", includeRoles template GUIDs) and
// the marker strings demo data and local post-deploy writes use
// ("DirectoryRole:GlobalAdmin", "AllAdmins", "upn:...", "group:...", "loc:...").

// ---------------------------------------------------------------- inputs

export interface CaSimUser {
  id?: string;
  userPrincipalName: string;
  displayName?: string;
  isGuest: boolean;
  // Lower-case role template GUIDs the user actively holds.
  roleTemplateIds: string[];
  // False when the user holds a role we could not resolve to a template id
  // (an unknown role name on an older snapshot) - a policy targeting roles
  // then evaluates "unknown" for this user instead of a confident "no".
  roleTemplateIdsComplete: boolean;
  // Ids of groups the user is a direct member of.
  groupIds: string[];
  // True for synthetic persona users ("a typical member of no special
  // group"): a group missing from the synced list is then a definite "no"
  // rather than "unknown". Found live: a tenant with more groups than the
  // sync fetches read "can't confirm" on nearly every tenant-wide question.
  groupMembershipComplete?: boolean;
}

export type CaSimClientAppType = "browser" | "mobileAppsAndDesktopClients" | "exchangeActiveSync" | "other";
export type CaSimPlatform = "windows" | "macOS" | "iOS" | "android" | "linux" | "unknown";
export type CaSimDeviceState = "compliant" | "hybridJoined" | "unmanaged";
export type CaSimRiskLevel = "none" | "low" | "medium" | "high";
export type CaSimInsiderRisk = "none" | "minor" | "moderate" | "elevated";

export type CaSimTarget =
  | { kind: "resource"; resource: "Office365" | "AzureManagement" | "AllResources" }
  | { kind: "userAction"; action: "urn:user:registersecurityinfo" | "urn:user:registerdevice" };

export interface CaSimLocation {
  // ISO 3166-1 alpha-2, upper-case. Null = the IP doesn't map to any country.
  country: string | null;
  // IP-range named locations the sign-in address falls inside.
  ipNamedLocationIds: string[];
}

export interface SignInContext {
  user: CaSimUser;
  target: CaSimTarget;
  clientAppType: CaSimClientAppType;
  platform: CaSimPlatform;
  device: CaSimDeviceState;
  authenticationFlow?: "deviceCodeFlow" | "authenticationTransfer";
  location: CaSimLocation;
  signInRisk: CaSimRiskLevel;
  userRisk: CaSimRiskLevel;
  insiderRisk: CaSimInsiderRisk;
}

export interface CaEnvironment {
  policies: CAPolicyRule[];
  // Undefined = never synced; location conditions then evaluate "unknown".
  namedLocations?: CaNamedLocation[];
  groups: TenantGroup[];
  // Risk conditions (sign-in / user risk) need Entra ID P2. Callers compute
  // this with entra-p2.ts's hasEntraP2Capability() - never an inline check.
  entraP2Licensed: boolean;
  securityDefaultsEnabled?: boolean;
  // Live-tenant policies persisted before Security Simulations Stage 1 lack
  // conditions the old mapper dropped (authentication flows, include groups,
  // user actions, insider risk, device filters). Evaluating them as-is is
  // wrong in BOTH directions - found live: a Microsoft-managed "block device
  // code flow" policy read as "block everything", and a groups-only policy
  // would read as "targets nobody". These evaluate "unknown" until re-synced.
  incompletePolicyIds?: string[];
}

// --------------------------------------------------------------- outputs

export type CaRequirementKind = "mfa" | "phishingResistantMfa" | "authenticationStrength" | "appProtection" | "passwordChange" | "other";

export interface CaRequirement {
  kind: CaRequirementKind;
  label: string;
}

export type CaConditionResult = "match" | "noMatch" | "unknown";

export interface CaExclusionHit {
  kind: "user" | "group" | "role" | "guests";
  ref: string;
}

export type CaGrantResult =
  | { kind: "block" }
  | { kind: "unsatisfiable"; reason: string }
  | { kind: "satisfied"; reason: string }
  // Each inner array is one alternative path; the user must complete every
  // requirement of at least one path.
  | { kind: "requires"; paths: CaRequirement[][] };

export interface CaPolicyTrace {
  policyId: string;
  policyName: string;
  state: CAPolicyRule["state"];
  source: "policy" | "securityDefaults";
  applies: "yes" | "no" | "unknown";
  // Human-readable reason for the applies value (first failing condition,
  // or "all conditions matched").
  reason: string;
  // Set when applies === "no" because the user was excluded - the fix
  // recommender uses this to test "what if the exclusion were removed".
  excludedBy?: CaExclusionHit[];
  // Set when applies !== "no".
  grant?: CaGrantResult;
  // Set when the policy covers only part of the target, e.g. "Only covers
  // SharePoint Online" - see CaOutcomeSummary.partialCoverage.
  partialResource?: string;
  sessionControls: string[];
  notes: string[];
}

export type CaOutcome = "blocked" | "challenged" | "allowed" | "indeterminate";

export interface CaOutcomeSummary {
  outcome: CaOutcome;
  blockedBy: { policyId: string; policyName: string; reason: string }[];
  // Per applying policy that needs something from the user.
  requirements: { policyId: string; policyName: string; paths: CaRequirement[][] }[];
  // Distinct requirement kinds across every policy - the "strongest" view.
  requirementKinds: CaRequirementKind[];
  sessionControls: { policyId: string; policyName: string; controls: string[] }[];
  // Policies whose applicability is unknown and that would block or
  // challenge if they applied.
  uncertainPolicies: { policyId: string; policyName: string; reason: string }[];
  // Policies that apply to only PART of the target (e.g. SharePoint only,
  // when the sign-in is to Office 365). They don't block or challenge the
  // sign-in as a whole - the rest of the target stays reachable - so they're
  // reported here instead of in blockedBy/requirements. Found live: a
  // SharePoint-only compliant-device policy read as "guests from abroad are
  // blocked" while Exchange and Teams stayed open.
  partialCoverage: { policyId: string; policyName: string; coverage: string; effect: "block" | "requires" }[];
}

export interface CaEvaluationResult {
  // Enabled policies only - what actually happens.
  enforced: CaOutcomeSummary;
  // Enabled + report-only policies treated as enabled - what WOULD happen
  // if every report-only policy were switched on.
  withReportOnly: CaOutcomeSummary;
  // Report-only policies that apply (or might) and would block/challenge.
  reportOnlyHits: { policyId: string; policyName: string; grant: CaGrantResult; applies: "yes" | "unknown" }[];
  trace: CaPolicyTrace[];
  evaluatedWithSecurityDefaults: boolean;
  notes: string[];
}

// ------------------------------------------------------------- constants

const AZURE_MANAGEMENT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013";
const EXCHANGE_ONLINE_APP_ID = "00000002-0000-0ff1-ce00-000000000000";
const SHAREPOINT_ONLINE_APP_ID = "00000003-0000-0ff1-ce00-000000000000";
const TEAMS_APP_ID = "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe";

// Keys (lower-case) that stand for each simulated target resource. "all" is
// handled separately. Office 365 sign-ins are modelled as touching Exchange,
// SharePoint and Teams together - a policy scoped to only one of them
// applies, with a note that it doesn't cover the rest.
const RESOURCE_KEYS: Record<"Office365" | "AzureManagement", { whole: string[]; parts: Record<string, string> }> = {
  Office365: {
    whole: ["office365"],
    parts: {
      [EXCHANGE_ONLINE_APP_ID]: "Exchange Online",
      exchangeonline: "Exchange Online",
      [SHAREPOINT_ONLINE_APP_ID]: "SharePoint Online",
      sharepointonline: "SharePoint Online",
      [TEAMS_APP_ID]: "Microsoft Teams",
      teams: "Microsoft Teams",
    },
  },
  AzureManagement: {
    whole: [AZURE_MANAGEMENT_APP_ID, "microsoftadminportals"],
    parts: {},
  },
};

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Microsoft's B2B collaboration guest - the "guest" persona this simulator models.
const SIM_GUEST_TYPE = "b2bcollaborationguest";

// ------------------------------------------------------ condition checks

type Tri = "yes" | "no" | "unknown";
const orTri = (values: Tri[]): Tri => (values.includes("yes") ? "yes" : values.includes("unknown") ? "unknown" : "no");

function lower(s: string): string {
  return s.trim().toLowerCase();
}

function findGroup(ref: string, groups: TenantGroup[]): TenantGroup | undefined {
  const r = lower(ref);
  return groups.find((g) => lower(g.id) === r || lower(g.displayName) === r || lower(g.mailNickname || "") === r);
}

// One users.include / users.exclude entry against the simulated user.
function userEntryMatches(entry: string, user: CaSimUser, groups: TenantGroup[], guestTypes: string[] | undefined): { hit: Tri; kind: CaExclusionHit["kind"] } {
  const e = entry.trim();
  const el = e.toLowerCase();

  if (el === "all") return { hit: "yes", kind: "user" };
  if (el === "none") return { hit: "no", kind: "user" };

  if (el === "guestsorexternalusers" || el === "guests") {
    if (!user.isGuest) return { hit: "no", kind: "guests" };
    const types = (guestTypes || []).map(lower);
    return { hit: types.length === 0 || types.includes(SIM_GUEST_TYPE) ? "yes" : "no", kind: "guests" };
  }

  const roleIds = resolveCaRoleReference(e);
  if (roleIds.length > 0) {
    if (roleIds.some((id) => user.roleTemplateIds.includes(id.toLowerCase()))) return { hit: "yes", kind: "role" };
    return { hit: user.roleTemplateIdsComplete ? "no" : "unknown", kind: "role" };
  }

  if (el.startsWith("upn:")) {
    return { hit: lower(e.slice(4)) === lower(user.userPrincipalName) ? "yes" : "no", kind: "user" };
  }

  if (el.startsWith("group:")) {
    const group = findGroup(e.slice(6), groups);
    if (!group) return { hit: user.groupMembershipComplete ? "no" : "unknown", kind: "group" };
    return { hit: groupContainsUser(group, user) ? "yes" : "no", kind: "group" };
  }

  // Live user object id, or a bare UPN.
  if (user.id && el === lower(user.id)) return { hit: "yes", kind: "user" };
  if (el === lower(user.userPrincipalName)) return { hit: "yes", kind: "user" };
  return { hit: "no", kind: "user" };
}

function groupContainsUser(group: TenantGroup, user: CaSimUser): boolean {
  if (user.groupIds.some((id) => lower(id) === lower(group.id))) return true;
  const upn = lower(user.userPrincipalName);
  return (group.members || []).some((m) => lower(m) === upn || (user.id !== undefined && lower(m) === lower(user.id)));
}

function roleIdMatches(roleId: string, user: CaSimUser): Tri {
  if (user.roleTemplateIds.includes(lower(roleId))) return "yes";
  return user.roleTemplateIdsComplete ? "no" : "unknown";
}

function groupIdMatches(groupId: string, user: CaSimUser, groups: TenantGroup[]): Tri {
  if (user.groupIds.some((id) => lower(id) === lower(groupId))) return "yes";
  // A group missing from the synced list (the groups fetch is capped - two
  // live tenants hit exactly 250) can't be answered either way.
  const group = findGroup(groupId, groups);
  if (!group) return user.groupMembershipComplete ? "no" : "unknown";
  return groupContainsUser(group, user) ? "yes" : "no";
}

function evaluateUsers(policy: CAPolicyRule, user: CaSimUser, groups: TenantGroup[]): { result: CaConditionResult; reason: string; excludedBy?: CaExclusionHit[] } {
  const u = policy.conditions.users;
  const includeEntries = u.include || [];
  const includeRoles = u.includeRoles || [];
  const includeGroups = u.includeGroupIds || [];

  if (includeEntries.length === 0 && includeRoles.length === 0 && includeGroups.length === 0) {
    return {
      result: "noMatch",
      reason: policy.conditions.clientApplications ? "Targets workload identities, not users" : "Targets no users",
    };
  }

  const included = orTri([
    ...includeEntries.map((e) => userEntryMatches(e, user, groups, u.includeGuestTypes).hit),
    ...includeRoles.map((r) => roleIdMatches(r, user)),
    ...includeGroups.map((g) => groupIdMatches(g, user, groups)),
  ]);

  const exclusionHits: CaExclusionHit[] = [];
  const exclusionUnknown: string[] = [];
  for (const e of u.exclude || []) {
    const { hit, kind } = userEntryMatches(e, user, groups, u.excludeGuestTypes);
    if (hit === "yes") exclusionHits.push({ kind, ref: e });
    if (hit === "unknown") exclusionUnknown.push(e);
  }
  for (const r of u.excludeRoles || []) {
    const hit = roleIdMatches(r, user);
    if (hit === "yes") exclusionHits.push({ kind: "role", ref: r });
    if (hit === "unknown") exclusionUnknown.push(r);
  }
  for (const g of u.excludeGroupIds || []) {
    const hit = groupIdMatches(g, user, groups);
    if (hit === "yes") exclusionHits.push({ kind: "group", ref: g });
    if (hit === "unknown") exclusionUnknown.push(g);
  }

  if (exclusionHits.length > 0) {
    return { result: "noMatch", reason: `User is excluded (${exclusionHits.map(describeExclusion).join(", ")})`, excludedBy: exclusionHits };
  }
  if (included === "no") return { result: "noMatch", reason: "User is not in the policy's included users, groups or roles" };
  if (included === "unknown") return { result: "unknown", reason: "Can't confirm whether the user is in the included groups or roles" };
  if (exclusionUnknown.length > 0) return { result: "unknown", reason: "Can't confirm whether the user is in an excluded group or role" };
  return { result: "match", reason: "User is in scope" };
}

export function describeExclusion(hit: CaExclusionHit): string {
  switch (hit.kind) {
    case "guests":
      return "guests and external users are excluded";
    case "role": {
      const ids = resolveCaRoleReference(hit.ref);
      const name = DIRECTORY_ROLE_TEMPLATES.find((r) => ids.includes(r.templateId))?.displayName;
      return `excluded role ${name || hit.ref}`;
    }
    case "group":
      return `excluded group ${hit.ref.replace(/^group:/i, "")}`;
    default:
      return `excluded user ${hit.ref.replace(/^upn:/i, "")}`;
  }
}

function evaluateApplications(policy: CAPolicyRule, target: CaSimTarget): { result: CaConditionResult; reason: string; notes: string[] } {
  const apps = policy.conditions.applications;
  const include = (apps.include || []).map(lower);
  const exclude = (apps.exclude || []).map(lower);
  const userActions = (apps.userActions || []).map(lower);

  if (target.kind === "userAction") {
    // Only a policy that names this user action covers it; resource-scoped
    // policies (even "All resources") are evaluated separately by Microsoft.
    return userActions.includes(target.action)
      ? { result: "match", reason: "Covers this user action", notes: [] }
      : { result: "noMatch", reason: "Doesn't cover this user action", notes: [] };
  }

  if (include.length === 0) {
    return { result: "noMatch", reason: userActions.length > 0 ? "Covers user actions only" : "Targets no resources", notes: [] };
  }
  if (include.includes("none")) return { result: "noMatch", reason: "Targets no resources (\"None\")", notes: [] };

  if (target.resource === "AllResources") {
    const excluded = exclude.length > 0;
    return include.includes("all")
      ? { result: "match", reason: "Targets all resources", notes: excluded ? ["Some resources are excluded from this policy"] : [] }
      : { result: "match", reason: "Targets specific resources", notes: ["Only covers some resources"] };
  }

  const keys = RESOURCE_KEYS[target.resource];
  const partNames = Object.keys(keys.parts);
  const wholeExcluded = keys.whole.some((k) => exclude.includes(lower(k)));
  if (wholeExcluded) return { result: "noMatch", reason: `${targetLabel(target)} is excluded`, notes: [] };

  const notes: string[] = [];
  const excludedParts = partNames.filter((k) => exclude.includes(k)).map((k) => keys.parts[k]);
  if (excludedParts.length > 0) notes.push(`Excludes ${[...new Set(excludedParts)].join(", ")}`);

  if (include.includes("all")) return { result: "match", reason: "Targets all resources", notes };
  if (keys.whole.some((k) => include.includes(lower(k)))) return { result: "match", reason: `Targets ${targetLabel(target)}`, notes };

  const coveredParts = [...new Set(partNames.filter((k) => include.includes(k)).map((k) => keys.parts[k]))];
  if (coveredParts.length > 0) {
    notes.push(`Only covers ${coveredParts.join(", ")}`);
    return { result: "match", reason: `Targets ${coveredParts.join(", ")}`, notes };
  }
  return { result: "noMatch", reason: `Doesn't target ${targetLabel(target)}`, notes: [] };
}

function evaluateClientApps(policy: CAPolicyRule, clientApp: CaSimClientAppType): { result: CaConditionResult; reason: string } {
  const types = (policy.conditions.clientAppTypes || []).map(lower);
  if (types.length === 0 || types.includes("all")) return { result: "match", reason: "All client apps" };
  const normalized = types.map((t) => (t === "eassupported" || t === "easunsupported" ? "exchangeactivesync" : t));
  return normalized.includes(lower(clientApp))
    ? { result: "match", reason: `Includes ${clientAppLabel(clientApp)}` }
    : { result: "noMatch", reason: `Doesn't include ${clientAppLabel(clientApp)} clients` };
}

function evaluatePlatforms(policy: CAPolicyRule, platform: CaSimPlatform): { result: CaConditionResult; reason: string } {
  const p = policy.conditions.platforms;
  const include = (p?.include || []).map(lower);
  const exclude = (p?.exclude || []).map(lower);
  if (include.length === 0) return { result: "match", reason: "Any platform" };
  const pl = lower(platform);
  if (exclude.includes(pl)) return { result: "noMatch", reason: `${platform} is excluded` };
  if (include.includes("all") || include.includes(pl)) return { result: "match", reason: `Includes ${platform}` };
  return { result: "noMatch", reason: `Doesn't include ${platform}` };
}

function locationRefHit(ref: string, loc: CaSimLocation, namedLocations: CaNamedLocation[] | undefined): Tri {
  const r = lower(ref);
  if (r === "all") return "yes";
  if (r === "alltrusted") {
    if (!namedLocations) return "unknown";
    return loc.ipNamedLocationIds.some((id) => namedLocations.find((n) => n.id === id)?.isTrusted) ? "yes" : "no";
  }
  const named = namedLocations?.find((n) => lower(n.id) === r);
  if (!named) return "unknown";
  if (named.kind === "country") {
    if (loc.country === null) return named.includeUnknownCountries ? "yes" : "no";
    return (named.countries || []).includes(loc.country.toUpperCase()) ? "yes" : "no";
  }
  return loc.ipNamedLocationIds.includes(named.id) ? "yes" : "no";
}

function evaluateLocations(policy: CAPolicyRule, loc: CaSimLocation, namedLocations: CaNamedLocation[] | undefined): { result: CaConditionResult; reason: string } {
  const include = policy.conditions.locations?.include || [];
  const exclude = policy.conditions.locations?.exclude || [];
  if (include.length === 0 && exclude.length === 0) return { result: "match", reason: "Any location" };

  const where = loc.country ? `from ${loc.country}` : "from an unknown country";
  const excluded = orTri(exclude.map((r) => locationRefHit(r, loc, namedLocations)));
  if (excluded === "yes") return { result: "noMatch", reason: `Sign-in ${where} is in an excluded location` };

  const included = include.length === 0 ? "yes" : orTri(include.map((r) => locationRefHit(r, loc, namedLocations)));
  if (included === "no") return { result: "noMatch", reason: `Sign-in ${where} isn't in an included location` };
  if (included === "unknown" || excluded === "unknown") {
    return { result: "unknown", reason: namedLocations ? "References a named location that no longer exists" : "Named locations haven't been synced" };
  }
  return { result: "match", reason: `Sign-in ${where} is in scope` };
}

function evaluateRiskList(levels: string[] | undefined, actual: string, label: string): { result: CaConditionResult; reason: string } | null {
  const list = (levels || []).map(lower).filter((l) => l !== "none" && l !== "hidden");
  if (list.length === 0) return null;
  return list.includes(lower(actual))
    ? { result: "match", reason: `${label} is ${actual}` }
    : { result: "noMatch", reason: `${label} ${actual} isn't one of ${list.join("/")}` };
}

function evaluateAuthFlows(policy: CAPolicyRule, flow: SignInContext["authenticationFlow"]): { result: CaConditionResult; reason: string } | null {
  const flows = (policy.conditions.authenticationFlows || []).map(lower);
  if (flows.length === 0) return null;
  return flow && flows.includes(lower(flow))
    ? { result: "match", reason: `Covers ${flowLabel(flow)}` }
    : { result: "noMatch", reason: "Only applies to device code / authentication transfer flows" };
}

// ------------------------------------------------------------ grant logic

type ControlState = { state: "met" } | { state: "unmet"; reason: string } | { state: "requires"; req: CaRequirement };

function evaluateControl(control: string, ctx: SignInContext): ControlState | { state: "block" } {
  const c = control.trim();
  const cl = c.toLowerCase();
  if (cl === "block") return { state: "block" };
  if (cl === "mfa") return { state: "requires", req: { kind: "mfa", label: "Multifactor authentication" } };
  if (cl.startsWith("authenticationstrength:")) {
    const name = c.slice("authenticationStrength:".length);
    return /phishing/i.test(name)
      ? { state: "requires", req: { kind: "phishingResistantMfa", label: `Phishing-resistant MFA (${name})` } }
      : { state: "requires", req: { kind: "authenticationStrength", label: `Authentication strength: ${name}` } };
  }
  if (cl === "compliantdevice") {
    return ctx.device === "compliant" ? { state: "met" } : { state: "unmet", reason: "requires a compliant device" };
  }
  if (cl === "domainjoineddevice") {
    return ctx.device === "hybridJoined" ? { state: "met" } : { state: "unmet", reason: "requires a Microsoft Entra hybrid joined device" };
  }
  if (cl === "approvedapplication" || cl === "compliantapplication" || cl === "appprotectionpolicy") {
    const mobile = ctx.platform === "iOS" || ctx.platform === "android";
    return mobile && ctx.clientAppType === "mobileAppsAndDesktopClients"
      ? { state: "requires", req: { kind: "appProtection", label: "Approved app with app protection policy" } }
      : { state: "unmet", reason: "requires an approved or app-protected mobile app, which this sign-in can't use" };
  }
  if (cl === "passwordchange") return { state: "requires", req: { kind: "passwordChange", label: "Secure password change" } };
  // Microsoft's newer "Require risk remediation" grant (user-risk policies):
  // the user self-remediates, which covers passwordless users too.
  if (cl === "riskremediation") return { state: "requires", req: { kind: "passwordChange", label: "Risk remediation" } };
  return { state: "requires", req: { kind: "other", label: `Control: ${c}` } };
}

// Microsoft always requires AND when password change is combined with MFA;
// otherwise an unsynced operator is assumed to be OR (the Graph default for
// single-control policies, and the common portal choice).
function effectiveOperator(policy: CAPolicyRule): { op: "AND" | "OR"; assumed: boolean } {
  if (policy.grantOperator) return { op: policy.grantOperator, assumed: false };
  const hasPasswordChange = policy.grantControls.some((g) => lower(g) === "passwordchange");
  return { op: hasPasswordChange ? "AND" : "OR", assumed: policy.grantControls.length > 1 };
}

export function evaluateGrant(policy: CAPolicyRule, ctx: SignInContext): { grant: CaGrantResult; notes: string[] } {
  const notes: string[] = [];
  const controls = policy.grantControls || [];
  if (controls.length === 0) return { grant: { kind: "satisfied", reason: "No grant controls (session controls only)" }, notes };

  const states = controls.map((c) => evaluateControl(c, ctx));
  if (states.some((s) => s.state === "block")) return { grant: { kind: "block" }, notes };

  const { op, assumed } = effectiveOperator(policy);
  if (assumed) notes.push(`Grant operator wasn't synced; assumed "${op === "OR" ? "require one of" : "require all of"}" the selected controls`);

  const typed = states as ControlState[];
  if (op === "OR") {
    const met = typed.find((s) => s.state === "met");
    if (met) return { grant: { kind: "satisfied", reason: "The device already satisfies one of the required controls" }, notes };
    const requires = typed.filter((s): s is { state: "requires"; req: CaRequirement } => s.state === "requires");
    if (requires.length === 0) {
      const reasons = typed.filter((s): s is { state: "unmet"; reason: string } => s.state === "unmet").map((s) => s.reason);
      return { grant: { kind: "unsatisfiable", reason: `Policy ${reasons.join(" or ")}` }, notes };
    }
    return { grant: { kind: "requires", paths: requires.map((r) => [r.req]) }, notes };
  }

  const unmet = typed.filter((s): s is { state: "unmet"; reason: string } => s.state === "unmet");
  if (unmet.length > 0) return { grant: { kind: "unsatisfiable", reason: `Policy ${unmet.map((u) => u.reason).join(" and ")}` }, notes };
  const reqs = typed.filter((s): s is { state: "requires"; req: CaRequirement } => s.state === "requires").map((s) => s.req);
  return reqs.length === 0
    ? { grant: { kind: "satisfied", reason: "The device satisfies every required control" }, notes }
    : { grant: { kind: "requires", paths: [reqs] }, notes };
}

function describeSessionControls(policy: CAPolicyRule): string[] {
  const sc = policy.sessionControls;
  if (!sc) return [];
  const out: string[] = [];
  if (sc.signInFrequency?.isEnabled) {
    out.push(
      sc.signInFrequency.frequencyInterval === "everyTime"
        ? "Sign-in frequency: every time"
        : `Sign-in frequency: ${sc.signInFrequency.value ?? "?"} ${sc.signInFrequency.type ?? ""}`.trim()
    );
  }
  if (sc.persistentBrowser?.isEnabled) out.push(`Persistent browser: ${sc.persistentBrowser.mode === "never" ? "never" : "always"}`);
  if (sc.applicationEnforcedRestrictions) out.push("App-enforced restrictions");
  if (sc.cloudAppSecurity?.isEnabled) out.push(`Defender for Cloud Apps session control${sc.cloudAppSecurity.type ? ` (${sc.cloudAppSecurity.type})` : ""}`);
  if (sc.tokenProtection) out.push("Token protection");
  if (sc.continuousAccessEvaluation === "disabled") out.push("Continuous access evaluation disabled");
  if (sc.continuousAccessEvaluation === "strictEnforcement" || sc.continuousAccessEvaluation === "strictLocation") out.push("Strict continuous access evaluation");
  return out;
}

// --------------------------------------------------------- policy tracing

export function tracePolicy(policy: CAPolicyRule, ctx: SignInContext, env: CaEnvironment, source: CaPolicyTrace["source"] = "policy"): CaPolicyTrace {
  const base: CaPolicyTrace = {
    policyId: policy.id,
    policyName: policy.name,
    state: policy.state,
    source,
    applies: "no",
    reason: "",
    sessionControls: [],
    notes: [],
  };

  if (policy.state === "disabled") return { ...base, reason: "Policy is disabled" };

  if (source === "policy" && env.incompletePolicyIds?.includes(policy.id)) {
    const { grant } = evaluateGrant(policy, ctx);
    return {
      ...base,
      applies: "unknown",
      reason: "Synced before simulation support, so some of its conditions weren't stored. Re-sync this tenant for an exact answer",
      grant,
    };
  }

  const hasRisk = (policy.conditions.signInRiskLevels || []).length > 0 || (policy.conditions.userRiskLevels || []).length > 0;
  if (hasRisk && !env.entraP2Licensed) {
    return { ...base, reason: "Uses sign-in or user risk, which needs Microsoft Entra ID P2 (not licensed), so it never evaluates" };
  }
  // Microsoft Entra ID Protection evaluates a B2B guest's risk in the guest's
  // HOME tenant; the resource tenant's risk-based policies don't see it.
  const riskActive = ctx.signInRisk !== "none" || ctx.userRisk !== "none";
  if (hasRisk && ctx.user.isGuest && riskActive) {
    return { ...base, reason: "Guest risk is evaluated by the guest's home organization, so this tenant's risk-based policies don't apply to guests" };
  }

  const users = evaluateUsers(policy, ctx.user, env.groups);
  const apps = evaluateApplications(policy, ctx.target);
  const checks: { result: CaConditionResult; reason: string }[] = [users, apps];

  // Every remaining condition is evaluated the same way for resource access
  // and user actions. Policies scoped to a user action rarely set these, and
  // Microsoft limits which conditions a "register or join devices" policy can
  // even use, so in practice they match.
  checks.push(evaluateClientApps(policy, ctx.clientAppType));
  checks.push(evaluatePlatforms(policy, ctx.platform));
  checks.push(evaluateLocations(policy, ctx.location, env.namedLocations));
  const signIn = evaluateRiskList(policy.conditions.signInRiskLevels, ctx.signInRisk, "Sign-in risk");
  if (signIn) checks.push(signIn);
  const userRisk = evaluateRiskList(policy.conditions.userRiskLevels, ctx.userRisk, "User risk");
  if (userRisk) checks.push(userRisk);
  const insider = evaluateRiskList(policy.conditions.insiderRiskLevels, ctx.insiderRisk, "Insider risk");
  if (insider) checks.push(insider);
  const flows = evaluateAuthFlows(policy, ctx.authenticationFlow);
  if (flows) checks.push(flows);

  const notes = [...apps.notes];
  if (policy.conditions.deviceFilter) {
    checks.push({ result: "unknown", reason: `Has a device filter (${policy.conditions.deviceFilter.mode}) the simulator can't evaluate` });
  }
  if ((policy.conditions.insiderRiskLevels || []).length > 0) {
    notes.push("Insider risk needs Microsoft Purview Insider Risk Management; licensing isn't verified here");
  }
  if ((policy.conditions.users.includeGroupIds || []).length > 0 || (policy.conditions.users.excludeGroupIds || []).length > 0) {
    notes.push("Group membership uses direct members from the last sync; nested groups aren't expanded");
  }

  const noMatch = checks.find((c) => c.result === "noMatch");
  if (noMatch) {
    return { ...base, reason: noMatch.reason, excludedBy: noMatch === users ? users.excludedBy : undefined, notes };
  }

  const { grant, notes: grantNotes } = evaluateGrant(policy, ctx);
  const unknown = checks.find((c) => c.result === "unknown");
  return {
    ...base,
    applies: unknown ? "unknown" : "yes",
    reason: unknown ? unknown.reason : "All conditions match",
    grant,
    partialResource: apps.notes.find((n) => n.startsWith("Only covers")),
    sessionControls: describeSessionControls(policy),
    notes: [...notes, ...grantNotes],
  };
}

// ------------------------------------------------------- security defaults

// Security defaults, modelled as three synthetic policies. Only used when
// security defaults are on (they can't coexist with Conditional Access).
export function securityDefaultsPolicies(): CAPolicyRule[] {
  const common = {
    baselineCode: null,
    state: "enabled" as const,
    modifiedDateTime: "",
    createdDateTime: "",
    matchesBaseline: false,
  };
  const allApps = { include: ["All"], exclude: [] };
  return [
    {
      ...common,
      id: "security-defaults-legacy",
      name: "Security defaults: block legacy authentication",
      grantControls: ["block"],
      conditions: { users: { include: ["All"], exclude: [] }, applications: allApps, clientAppTypes: ["exchangeActiveSync", "other"] },
    },
    {
      ...common,
      id: "security-defaults-admins",
      name: "Security defaults: MFA for administrators",
      grantControls: ["mfa"],
      conditions: { users: { include: ["AllAdmins"], exclude: [] }, applications: allApps, clientAppTypes: ["all"] },
    },
    {
      ...common,
      id: "security-defaults-users",
      name: "Security defaults: MFA when Microsoft deems it necessary",
      grantControls: ["mfa"],
      conditions: { users: { include: ["All"], exclude: [] }, applications: allApps, clientAppTypes: ["browser", "mobileAppsAndDesktopClients"] },
    },
  ];
}

// ------------------------------------------------------------ aggregation

function summarize(traces: CaPolicyTrace[]): CaOutcomeSummary {
  const summary: CaOutcomeSummary = {
    outcome: "allowed",
    blockedBy: [],
    requirements: [],
    requirementKinds: [],
    sessionControls: [],
    uncertainPolicies: [],
    partialCoverage: [],
  };

  for (const t of traces) {
    if (t.applies === "no" || !t.grant) continue;
    if (t.applies === "unknown") {
      if (t.grant.kind !== "satisfied") summary.uncertainPolicies.push({ policyId: t.policyId, policyName: t.policyName, reason: t.reason });
      continue;
    }
    if (t.partialResource && t.grant.kind !== "satisfied") {
      summary.partialCoverage.push({
        policyId: t.policyId,
        policyName: t.policyName,
        coverage: t.partialResource.replace(/^Only covers /, ""),
        effect: t.grant.kind === "requires" ? "requires" : "block",
      });
      continue;
    }
    if (t.grant.kind === "block") summary.blockedBy.push({ policyId: t.policyId, policyName: t.policyName, reason: "Blocks access" });
    else if (t.grant.kind === "unsatisfiable") summary.blockedBy.push({ policyId: t.policyId, policyName: t.policyName, reason: t.grant.reason });
    else if (t.grant.kind === "requires") summary.requirements.push({ policyId: t.policyId, policyName: t.policyName, paths: t.grant.paths });
    if (t.sessionControls.length > 0) summary.sessionControls.push({ policyId: t.policyId, policyName: t.policyName, controls: t.sessionControls });
  }

  const kinds = new Set<CaRequirementKind>();
  for (const r of summary.requirements) for (const path of r.paths) for (const req of path) kinds.add(req.kind);
  summary.requirementKinds = [...kinds];

  if (summary.blockedBy.length > 0) summary.outcome = "blocked";
  else if (summary.uncertainPolicies.length > 0) summary.outcome = "indeterminate";
  else if (summary.requirements.length > 0) summary.outcome = "challenged";
  return summary;
}

export function evaluateSignIn(ctx: SignInContext, env: CaEnvironment): CaEvaluationResult {
  const notes: string[] = [];
  const hasEnabledPolicy = env.policies.some((p) => p.state === "enabled");
  const useSecurityDefaults = env.securityDefaultsEnabled === true && !hasEnabledPolicy;
  if (useSecurityDefaults) notes.push("Security defaults are on, so Microsoft's fixed baseline protections apply instead of Conditional Access");

  const trace = [
    ...env.policies.map((p) => tracePolicy(p, ctx, env)),
    ...(useSecurityDefaults ? securityDefaultsPolicies().map((p) => tracePolicy(p, ctx, env, "securityDefaults")) : []),
  ];

  const enforcedTraces = trace.filter((t) => t.state === "enabled");
  const allTraces = trace.filter((t) => t.state === "enabled" || t.state === "enabledForReportingButNotEnforced");

  const reportOnlyHits = trace
    .filter((t) => t.state === "enabledForReportingButNotEnforced" && t.applies !== "no" && t.grant && t.grant.kind !== "satisfied")
    .map((t) => ({ policyId: t.policyId, policyName: t.policyName, grant: t.grant!, applies: t.applies as "yes" | "unknown" }));

  if (!env.namedLocations) notes.push("Named locations haven't been synced yet; location conditions can't be evaluated");
  if ((env.incompletePolicyIds || []).length > 0) {
    notes.push(`${env.incompletePolicyIds!.length} policies were synced before simulation support; re-sync this tenant for exact results`);
  }

  return {
    enforced: summarize(enforcedTraces),
    withReportOnly: summarize(allTraces),
    reportOnlyHits,
    trace,
    evaluatedWithSecurityDefaults: useSecurityDefaults,
    notes,
  };
}

// ----------------------------------------------------------------- labels

export function targetLabel(target: CaSimTarget): string {
  if (target.kind === "userAction") {
    return target.action === "urn:user:registerdevice" ? "device registration" : "security info registration";
  }
  return target.resource === "Office365" ? "Office 365" : target.resource === "AzureManagement" ? "Azure management" : "all resources";
}

export function clientAppLabel(c: CaSimClientAppType): string {
  switch (c) {
    case "browser":
      return "browser";
    case "mobileAppsAndDesktopClients":
      return "mobile and desktop app";
    case "exchangeActiveSync":
      return "Exchange ActiveSync";
    default:
      return "other legacy";
  }
}

export function flowLabel(flow: NonNullable<SignInContext["authenticationFlow"]>): string {
  return flow === "deviceCodeFlow" ? "device code flow" : "authentication transfer";
}

export function isGuid(value: string): boolean {
  return GUID_RE.test(value);
}
