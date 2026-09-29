import { TenantSecuritySnapshot, UserMfaProfile } from "../types";
import { hasEntraP2Capability } from "../utils/entra-p2";
import { GLOBAL_ADMIN_TEMPLATE_ID, getRoleTemplateByName, roleNamesToTemplateIds } from "../utils/directory-role-templates";
import { CaEnvironment, CaSimUser } from "./ca-policy-evaluator";

// Builds ca-policy-evaluator.ts inputs from a TenantSecuritySnapshot, and
// finds likely emergency-access (break-glass) accounts. Kept apart from the
// evaluator so the engine itself stays independent of the snapshot shape.

export function buildCaEnvironment(snapshot: TenantSecuritySnapshot): CaEnvironment {
  const policies = snapshot.conditionalAccess?.policies || [];
  return {
    policies,
    // ca-environment-mapper always sets includeGroupIds (at least []), so its
    // absence on a live tenant's policy means the old mapper stored it. Demo
    // policies are complete by definition - they are exactly what they say.
    incompletePolicyIds: snapshot.tenant?.isDemo
      ? []
      : policies.filter((p) => !Array.isArray(p.conditions?.users?.includeGroupIds)).map((p) => p.id),
    namedLocations: snapshot.conditionalAccess?.namedLocations,
    groups: snapshot.groups || [],
    entraP2Licensed: hasEntraP2Capability(snapshot),
    securityDefaultsEnabled: snapshot.identitySettings?.securityDefaultsEnabled,
  };
}

export interface SimAccount {
  id: string;
  userPrincipalName: string;
  displayName: string;
  // "directoryRoles": role data came from real directory-role membership.
  // "inferred": an older snapshot without role template ids, where
  // adminRoles may include the "Global Administrator" placeholder the sync
  // writes when only the MFA registration report flags someone as admin.
  roleSource?: "directoryRoles" | "inferred";
  roles?: string[];
  // Set when detectLikelyBreakGlassAccounts() flags this account - the
  // picker warns, since an emergency-access account is excluded from most
  // policies by design and its results don't represent a normal admin.
  breakGlassReasons?: string[];
}

export interface SimAccountLists {
  globalAdmins: SimAccount[];
  otherAdmins: SimAccount[];
  standardUsers: SimAccount[];
  guests: SimAccount[];
}

function isGuestUpn(upn: string): boolean {
  return upn.toLowerCase().includes("#ext#");
}

function roleTemplateIdsFor(profile: UserMfaProfile | undefined): { ids: string[]; complete: boolean; source: "directoryRoles" | "inferred" } {
  if (!profile) return { ids: [], complete: true, source: "directoryRoles" };
  if (profile.adminRoleTemplateIds) {
    return { ids: profile.adminRoleTemplateIds.map((id) => id.toLowerCase()), complete: true, source: "directoryRoles" };
  }
  const names = profile.adminRoles || [];
  const ids = roleNamesToTemplateIds(names).map((id) => id.toLowerCase());
  const allResolved = names.every((n) => getRoleTemplateByName(n) !== undefined);
  return { ids, complete: allResolved, source: "inferred" };
}

// The accounts the "Sign in as" picker offers. Global Admins come only from
// role data; when a snapshot predates role template ids the list is still
// built from role names but flagged "inferred".
export function listSimAccounts(snapshot: TenantSecuritySnapshot): SimAccountLists {
  const profiles = snapshot.mfaAudit || [];
  const directory = snapshot.accountClassification?.users || [];
  const lists: SimAccountLists = { globalAdmins: [], otherAdmins: [], standardUsers: [], guests: [] };
  const seen = new Set<string>();
  const breakGlass = detectLikelyBreakGlassAccounts(snapshot);

  for (const p of profiles) {
    if (!p.accountEnabled) continue;
    seen.add(p.id);
    const bg = isLikelyBreakGlassRef(p.id, breakGlass) || isLikelyBreakGlassRef(p.userPrincipalName, breakGlass);
    const account: SimAccount = { id: p.id, userPrincipalName: p.userPrincipalName, displayName: p.displayName, breakGlassReasons: bg?.reasons };
    const dirEntry = directory.find((d) => d.id === p.id);
    if (dirEntry?.classification === "guest" || isGuestUpn(p.userPrincipalName)) {
      lists.guests.push(account);
      continue;
    }
    const roles = roleTemplateIdsFor(p);
    if (roles.ids.length > 0 || (p.adminRoles || []).length > 0) {
      const withRoles = { ...account, roleSource: roles.source, roles: p.adminRoles || [] };
      if (roles.ids.includes(GLOBAL_ADMIN_TEMPLATE_ID)) lists.globalAdmins.push(withRoles);
      else lists.otherAdmins.push(withRoles);
      continue;
    }
    if (dirEntry && dirEntry.classification !== "licensed") continue;
    lists.standardUsers.push(account);
  }

  // Guests often have no MFA registration row - fall back to the directory list.
  for (const d of directory) {
    if (seen.has(d.id) || !d.accountEnabled) continue;
    if (d.classification === "guest") lists.guests.push({ id: d.id, userPrincipalName: d.userPrincipalName, displayName: d.displayName });
  }

  const byName = (a: SimAccount, b: SimAccount) => a.displayName.localeCompare(b.displayName);
  lists.globalAdmins.sort(byName);
  lists.otherAdmins.sort(byName);
  lists.standardUsers.sort(byName);
  lists.guests.sort(byName);
  return lists;
}

export function buildSimUser(snapshot: TenantSecuritySnapshot, userId: string): CaSimUser | undefined {
  const profile = (snapshot.mfaAudit || []).find((p) => p.id === userId);
  const dirEntry = (snapshot.accountClassification?.users || []).find((d) => d.id === userId);
  const upn = profile?.userPrincipalName || dirEntry?.userPrincipalName;
  if (!upn) return undefined;

  const roles = roleTemplateIdsFor(profile);
  const upnLower = upn.toLowerCase();
  const groupIds = (snapshot.groups || [])
    .filter((g) => (g.members || []).some((m) => m.toLowerCase() === upnLower || m === userId))
    .map((g) => g.id);

  return {
    id: userId,
    userPrincipalName: upn,
    displayName: profile?.displayName || dirEntry?.displayName,
    isGuest: dirEntry?.classification === "guest" || isGuestUpn(upn),
    roleTemplateIds: roles.ids,
    roleTemplateIdsComplete: roles.complete,
    groupIds,
  };
}

// A hypothetical user for when a persona has no real account to pick (for
// example a tenant with no guests yet). Never matches user-specific
// includes/excludes - only "All", guest and role targeting.
export function buildSyntheticSimUser(kind: "globalAdmin" | "user" | "guest"): CaSimUser {
  return {
    userPrincipalName: kind === "guest" ? "simulated.guest_example.com#EXT#@simulated" : `simulated.${kind}@simulated`,
    displayName: kind === "globalAdmin" ? "Simulated Global Administrator" : kind === "guest" ? "Simulated guest" : "Simulated user",
    isGuest: kind === "guest",
    roleTemplateIds: kind === "globalAdmin" ? [GLOBAL_ADMIN_TEMPLATE_ID] : [],
    roleTemplateIdsComplete: true,
    groupIds: [],
  };
}

// ------------------------------------------------------------ break-glass

export interface BreakGlassCandidate {
  // The exclusion entry exactly as it appears on policies (GUID, "upn:...",
  // "group:...", or an excluded group id).
  ref: string;
  kind: "user" | "group";
  userPrincipalName?: string;
  displayName?: string;
  excludedFromCount: number;
  eligiblePolicyCount: number;
  reasons: string[];
}

const BREAK_GLASS_NAME = /(break.?glass|emergency|bg[-_.]?admin|glass.?break)/i;

// Accounts that look like emergency-access (break-glass) accounts: excluded
// from most enabled/report-only policies, or named like one. Per the user's
// review decision these are surfaced as a WARNING to confirm, never silently
// treated as intended or as a gap.
export function detectLikelyBreakGlassAccounts(snapshot: TenantSecuritySnapshot): BreakGlassCandidate[] {
  const policies = (snapshot.conditionalAccess?.policies || []).filter((p) => p.state !== "disabled");
  if (policies.length === 0) return [];

  const counts = new Map<string, { kind: "user" | "group"; count: number }>();
  for (const p of policies) {
    const refs = new Set<string>();
    for (const e of p.conditions.users.exclude || []) {
      if (e.toLowerCase() === "guestsorexternalusers") continue;
      refs.add(e);
    }
    for (const g of p.conditions.users.excludeGroupIds || []) refs.add(`__group__${g}`);
    for (const r of refs) {
      const isGroup = r.startsWith("__group__") || r.toLowerCase().startsWith("group:");
      const key = r.replace(/^__group__/, "");
      const entry = counts.get(key) || { kind: isGroup ? "group" : "user", count: 0 };
      entry.count += 1;
      counts.set(key, entry);
    }
  }

  const users = [...(snapshot.mfaAudit || []), ...(snapshot.accountClassification?.users || [])];
  const candidates: BreakGlassCandidate[] = [];
  for (const [ref, { kind, count }] of counts) {
    const bare = ref.replace(/^(upn:|group:)/i, "");
    const user = kind === "user" ? users.find((u) => u.id === bare || u.userPrincipalName.toLowerCase() === bare.toLowerCase()) : undefined;
    const group = kind === "group" ? (snapshot.groups || []).find((g) => g.id === bare || g.displayName.toLowerCase() === bare.toLowerCase()) : undefined;
    const label = user?.userPrincipalName || group?.displayName || bare;
    const displayName = user?.displayName || group?.displayName;

    const reasons: string[] = [];
    if (BREAK_GLASS_NAME.test(label) || (displayName && BREAK_GLASS_NAME.test(displayName))) reasons.push("Named like an emergency-access account");
    const share = count / policies.length;
    if (count >= 2 && share >= 0.6) reasons.push(`Excluded from ${count} of ${policies.length} active policies`);
    if (reasons.length === 0) continue;

    candidates.push({
      ref,
      kind,
      userPrincipalName: user?.userPrincipalName,
      displayName,
      excludedFromCount: count,
      eligiblePolicyCount: policies.length,
      reasons,
    });
  }

  return candidates.sort((a, b) => b.excludedFromCount - a.excludedFromCount);
}

export function isLikelyBreakGlassRef(ref: string, candidates: BreakGlassCandidate[]): BreakGlassCandidate | undefined {
  const r = ref.replace(/^(upn:|group:)/i, "").toLowerCase();
  return candidates.find((c) => c.ref.replace(/^(upn:|group:)/i, "").toLowerCase() === r);
}
