import { CAPolicyRule, TenantSecuritySnapshot } from "../types";
import {
  FixGuideBreakGlass,
  FixGuideContext,
  FixGuideDefinition,
  FixGuideItem,
  FixGuideStep,
  GuideCommand,
  ProposedCaPolicy,
  SHELL_CONNECT,
  getFixGuideDefinition,
} from "../data/scenario-fix-guides";
import { detectLikelyBreakGlassAccounts, isLikelyBreakGlassRef, listSimAccounts } from "./ca-sim-context";
import { DIRECTORY_ROLE_TEMPLATES, getRoleTemplateById } from "../utils/directory-role-templates";
import { smtpAuthEnabledFor } from "./security-posture-mapper";
import { mapConditionalAccessPolicy } from "./ca-policy-mapper";
import { mapCaBetaSessionExtras } from "./ca-environment-mapper";
import { PolicyImpactPreview, previewPolicyImpact } from "./ca-policy-impact";
import { normalizeCountryCode, UNKNOWN_COUNTRY } from "../utils/sign-in-country";
import { hasEntraP2Capability } from "../utils/entra-p2";

// Turns a guide definition into the guide for ONE tenant: commands carry
// that tenant's real object ids and break-glass accounts, and anything that
// couldn't be filled in is listed as a warning. Pure.

const SHAREPOINT_ADMIN_PLACEHOLDER = "https://admin.microsoft.com/sharepoint";

export interface ResolvedCommand extends GuideCommand {
  // The connect line for this shell, with the scopes this command needs.
  connect: string;
  install: string;
  shellLabel: string;
}

export interface ResolvedFixGuideStep extends Omit<FixGuideStep, "command"> {
  command?: ResolvedCommand;
}

// What a proposed Conditional Access policy would have done to this tenant's
// synced sign-ins (ca-policy-impact.ts), or why that can't be shown.
export type FixGuidePreview = { available: true; result: PolicyImpactPreview } | { available: false; reason: string };

export interface ResolvedFixGuide extends Omit<FixGuideDefinition, "steps" | "verify" | "undo" | "missing" | "proposedPolicy"> {
  tenantName: string;
  preview?: FixGuidePreview;
  steps: ResolvedFixGuideStep[];
  verify: { inClarity: string; command?: ResolvedCommand };
  undo: { text: string; command?: ResolvedCommand };
  warnings: string[];
}

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isGuestUpn = (upn: string | undefined) => !!upn && upn.toLowerCase().includes("#ext#");

// Break-glass accounts as object ids (CA exclusions need ids, not names).
function breakGlassAccounts(snapshot: TenantSecuritySnapshot): FixGuideBreakGlass[] {
  const users = snapshot.mfaAudit || [];
  const out: FixGuideBreakGlass[] = [];
  for (const candidate of detectLikelyBreakGlassAccounts(snapshot)) {
    if (candidate.kind !== "user") continue;
    const ref = candidate.ref.replace(/^upn:/i, "");
    const byId = GUID.test(ref) ? users.find((u) => u.id.toLowerCase() === ref.toLowerCase()) : undefined;
    const byUpn = users.find((u) => u.userPrincipalName.toLowerCase() === (candidate.userPrincipalName || ref).toLowerCase());
    const objectId = GUID.test(ref) ? ref : byUpn?.id;
    if (!objectId || !GUID.test(objectId)) continue;
    const label = byId?.userPrincipalName || byUpn?.userPrincipalName || candidate.userPrincipalName || candidate.displayName || objectId;
    if (!out.some((o) => o.objectId === objectId)) out.push({ objectId, label });
  }
  return out;
}

// Guests holding directory roles, from PIM data first, then MFA profiles.
function guestRoleItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  const items: FixGuideItem[] = [];
  for (const a of snapshot.privilegedRoleAssignments?.assignments || []) {
    if (!isGuestUpn(a.principalUserPrincipalName)) continue;
    const roleName = getRoleTemplateById(a.roleTemplateId)?.displayName || "Directory role";
    items.push({ label: `${a.principalUserPrincipalName} (${roleName}, ${a.kind})`, principalId: a.principalId, userPrincipalName: a.principalUserPrincipalName, roleTemplateId: a.roleTemplateId, roleName, assignmentKind: a.kind });
  }
  for (const u of snapshot.mfaAudit || []) {
    if (!u.isAdmin || !isGuestUpn(u.userPrincipalName)) continue;
    const ids = u.adminRoleTemplateIds || [];
    if (ids.length === 0) {
      if (!items.some((i) => i.principalId === u.id)) items.push({ label: `${u.userPrincipalName} (${(u.adminRoles || []).join(", ") || "role not known"})`, principalId: u.id, userPrincipalName: u.userPrincipalName });
      continue;
    }
    for (const roleTemplateId of ids) {
      if (items.some((i) => i.principalId === u.id && i.roleTemplateId === roleTemplateId)) continue;
      const roleName = getRoleTemplateById(roleTemplateId)?.displayName || "Directory role";
      items.push({ label: `${u.userPrincipalName} (${roleName})`, principalId: u.id, userPrincipalName: u.userPrincipalName, roleTemplateId, roleName, assignmentKind: "activePermanent" });
    }
  }
  return items;
}

// Mailboxes that can use SMTP AUTH, and mailboxes with POP or IMAP on.
function smtpAuthMailboxItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  const ex = snapshot.exchangeSecurity;
  return (ex?.casMailboxes || []).filter((m) => smtpAuthEnabledFor(m, ex?.smtpClientAuthDisabledOrgWide) === true).map((m) => ({ label: m.primarySmtpAddress, address: m.primarySmtpAddress }));
}
function popImapMailboxItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.exchangeSecurity?.casMailboxes || [])
    .filter((m) => m.popEnabled || m.imapEnabled)
    .map((m) => ({ label: `${m.primarySmtpAddress} (${[m.popEnabled ? "POP" : "", m.imapEnabled ? "IMAP" : ""].filter(Boolean).join(" + ")})`, address: m.primarySmtpAddress }));
}
// Sites that allow Anyone links.
function anyoneSiteItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.sharePoint?.sites || []).filter((s) => s.sharingCapability === "Anyone").map((s) => ({ label: s.siteName || s.siteUrl, url: s.siteUrl }));
}

// https://contoso.sharepoint.com/sites/x -> https://contoso-admin.sharepoint.com
export function sharePointAdminUrlFrom(snapshot: TenantSecuritySnapshot): string | undefined {
  for (const site of snapshot.sharePoint?.sites || []) {
    const m = /^https:\/\/([a-z0-9-]+?)(?:-my)?\.sharepoint\.com/i.exec(site.siteUrl || "");
    if (m) return `https://${m[1].toLowerCase()}-admin.sharepoint.com`;
  }
  return undefined;
}

// Country named locations that don't cover addresses with no known country.
function unknownCountryLocationItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.conditionalAccess?.namedLocations || [])
    .filter((l) => l.kind === "country" && !l.includeUnknownCountries)
    .map((l) => ({ label: `${l.displayName} (${(l.countries || []).join(", ") || "no countries"})`, principalId: l.id }));
}
// Switched-on policies that turn continuous access evaluation off.
function caeDisabledPolicyItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.conditionalAccess?.policies || []).filter((p) => p.state === "enabled" && p.sessionControls?.continuousAccessEvaluation === "disabled").map((p) => ({ label: p.name, principalId: p.id }));
}

// Countries of successful sign-ins, busiest first.
export function signInCountries(snapshot: TenantSecuritySnapshot): { code: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const e of snapshot.signIns || []) {
    if (e.status !== "success") continue;
    const code = normalizeCountryCode(e.location?.country);
    if (code === UNKNOWN_COUNTRY) continue;
    counts.set(code, (counts.get(code) || 0) + 1);
  }
  return [...counts.entries()].map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count || a.code.localeCompare(b.code));
}

// ------------------------------------------------ Stage 3 review item sources
// Each mirrors the check that offers the guide (security-scenarios.ts), so
// the guide acts on exactly what the check reported.

const GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10";
const USER_ADMIN = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de";
// Roles the standing-access, standing-deleters and exchange-admins checks look at.
const STANDING_ROLE_IDS = new Set([...DIRECTORY_ROLE_TEMPLATES.filter((t) => t.isPrivileged).map((t) => t.templateId), USER_ADMIN, EXCHANGE_ADMIN]);

function isBreakGlassRef(snapshot: TenantSecuritySnapshot, ...refs: (string | undefined)[]): boolean {
  const candidates = detectLikelyBreakGlassAccounts(snapshot);
  return refs.some((r) => !!r && !!isLikelyBreakGlassRef(r, candidates));
}

function mfaUnregisteredItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.mfaAudit || [])
    .filter((u) => u.accountEnabled && !u.mfaRegistered && !isGuestUpn(u.userPrincipalName))
    .map((u) => ({ label: u.userPrincipalName, principalId: u.id, userPrincipalName: u.userPrincipalName }));
}

// One item per (account, policy) where an enabled or report-only policy
// excludes a non-break-glass member account by name.
function individualExclusionItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  const lists = listSimAccounts(snapshot);
  const accounts = [...lists.globalAdmins, ...lists.otherAdmins, ...lists.standardUsers].filter((a) => a.excludedFrom && !a.breakGlassReasons);
  const items: FixGuideItem[] = [];
  for (const a of accounts) {
    for (const p of snapshot.conditionalAccess?.policies || []) {
      if (p.state === "disabled") continue;
      const ref = (p.conditions.users.exclude || []).find((e) => {
        const key = e.replace(/^upn:/i, "").toLowerCase();
        return key === a.id.toLowerCase() || key === a.userPrincipalName.toLowerCase();
      });
      if (!ref) continue;
      items.push({ label: `${a.userPrincipalName}: ${p.name}`, principalId: a.id, userPrincipalName: a.userPrincipalName, policyId: p.id, policyName: p.name, excludeRef: ref.replace(/^upn:/i, "") });
    }
  }
  return items;
}

function riskyConsentItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.oauthConsentGrants?.grants || [])
    .filter((g) => g.consentType === "Principal" && g.highRiskScopes.length > 0 && !g.isMicrosoftApp && g.publisherVerified !== true)
    .map((g) => ({ label: `${g.appDisplayName || g.servicePrincipalId} (${g.userCount} user(s)): ${g.highRiskScopes.join(", ")}`, principalId: g.servicePrincipalId }));
}

const ROLE_GRANTING = /RoleManagement\.ReadWrite\.Directory|AppRoleAssignment\.ReadWrite\.All|Directory\.ReadWrite\.All/i;
function riskyAppRegistrationItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.appRegistrations || [])
    .filter((a) => a.riskCategory === "critical" || a.riskCategory === "high" || a.highPrivilegePermissions.some((p) => ROLE_GRANTING.test(p)))
    .map((a) => ({ label: `${a.displayName}: ${a.highPrivilegePermissions.join(", ")}`, appId: a.appId, permissions: a.highPrivilegePermissions }));
}

// Role holders from PIM data when synced, otherwise from directory roles.
function roleHolderItems(snapshot: TenantSecuritySnapshot, roleIds: Set<string>, onlyStanding: boolean): FixGuideItem[] {
  const items: FixGuideItem[] = [];
  const pr = snapshot.privilegedRoleAssignments;
  if (pr) {
    for (const a of pr.assignments) {
      if (!roleIds.has(a.roleTemplateId) || a.principalType === "servicePrincipal" || a.principalType === "group") continue;
      if (onlyStanding && a.kind !== "activePermanent") continue;
      const upn = a.principalUserPrincipalName || a.principalDisplayName || a.principalId;
      const roleName = getRoleTemplateById(a.roleTemplateId)?.displayName || "Directory role";
      items.push({ label: `${upn} (${roleName}, ${a.kind})`, principalId: a.principalId, userPrincipalName: a.principalUserPrincipalName, roleTemplateId: a.roleTemplateId, roleName, assignmentKind: a.kind });
    }
    return items;
  }
  for (const u of snapshot.mfaAudit || []) {
    for (const id of (u.adminRoleTemplateIds || []).map((x) => x.toLowerCase())) {
      if (!roleIds.has(id)) continue;
      const roleName = getRoleTemplateById(id)?.displayName || "Directory role";
      items.push({ label: `${u.userPrincipalName} (${roleName})`, principalId: u.id, userPrincipalName: u.userPrincipalName, roleTemplateId: id, roleName, assignmentKind: "activePermanent" });
    }
  }
  return items;
}

// One line per Global Administrator, whatever the assignment kind.
function globalAdminItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  const seen = new Set<string>();
  return roleHolderItems(snapshot, new Set([GLOBAL_ADMIN]), false).filter((i) => {
    if (!i.principalId || seen.has(i.principalId)) return false;
    seen.add(i.principalId);
    return true;
  });
}

function standingAdminItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return roleHolderItems(snapshot, STANDING_ROLE_IDS, true).filter((i) => !isBreakGlassRef(snapshot, i.principalId, i.userPrincipalName));
}

function roleGroupOwnerItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  const adminUpns = new Set((snapshot.mfaAudit || []).filter((u) => u.isAdmin).map((u) => u.userPrincipalName.toLowerCase()));
  return (snapshot.groups || [])
    .filter((g) => g.isAssignableToRole)
    .flatMap((g) => (g.owners || []).filter((o) => !adminUpns.has(o.toLowerCase())).map((o) => ({ label: `${g.displayName}: ${o}`, groupId: g.id, ownerUpn: o })));
}

function externalMailboxForwardItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.emailForwarding || [])
    .filter((r) => r.isExternal && r.state === "Enabled" && r.scope !== "transport_rule")
    .map((r) => ({
      label: `${r.mailboxOwner || r.name} → ${r.forwardingAddress}${r.scope === "inbox_rule" ? ` (rule "${r.name}")` : " (mailbox forwarding)"}`,
      address: r.mailboxOwner,
      ruleName: r.scope === "inbox_rule" ? r.name : undefined,
      forwardKind: r.scope === "inbox_rule" ? ("inboxRule" as const) : ("mailboxForwarding" as const),
    }));
}

function externalTransportRuleItems(snapshot: TenantSecuritySnapshot): FixGuideItem[] {
  return (snapshot.mailflowTransportRules || []).filter((r) => r.state === "Enabled" && r.redirectsExternally).map((r) => ({ label: `${r.name} → ${r.externalRedirectAddress || "external address"}`, ruleName: r.name }));
}

// Which offending items each guide works on.
const ITEM_SOURCES: Record<string, (snapshot: TenantSecuritySnapshot) => FixGuideItem[]> = {
  "remove-guest-admin-roles": guestRoleItems,
  "restrict-smtp-auth-mailboxes": smtpAuthMailboxItems,
  "disable-pop-imap": popImapMailboxItems,
  "sharepoint-restrict-anyone-sites": anyoneSiteItems,
  "include-unknown-countries": unknownCountryLocationItems,
  "keep-cae-on": caeDisabledPolicyItems,
  "mfa-registration-drive": mfaUnregisteredItems,
  "remove-individual-exclusions": individualExclusionItems,
  "revoke-risky-app-consent": riskyConsentItems,
  "review-app-permissions": riskyAppRegistrationItems,
  "right-size-global-admins": globalAdminItems,
  "make-admin-roles-eligible": standingAdminItems,
  "remove-role-group-owners": roleGroupOwnerItems,
  "stop-external-mailbox-forwarding": externalMailboxForwardItems,
  "disable-external-transport-rules": externalTransportRuleItems,
};

export function buildFixGuideContext(guideId: string, snapshot: TenantSecuritySnapshot): FixGuideContext {
  const countries = signInCountries(snapshot);
  return {
    tenantName: snapshot.tenant.displayName,
    tenantId: snapshot.tenant.credentials?.tenantId || undefined,
    breakGlass: breakGlassAccounts(snapshot),
    items: ITEM_SOURCES[guideId]?.(snapshot) || [],
    sharePointAdminUrl: sharePointAdminUrlFrom(snapshot),
    homeCountry: countries[0]?.code,
    observedCountries: countries.slice(1),
    entraP2Licensed: hasEntraP2Capability(snapshot),
  };
}

// Built-in authentication strengths by id, so the mapped policy carries the
// name the What If engine reads ("Phishing-resistant MFA" -> phishing-resistant).
const BUILT_IN_STRENGTH_NAMES: Record<string, string> = {
  "00000000-0000-0000-0000-000000000002": "Multifactor authentication",
  "00000000-0000-0000-0000-000000000003": "Passwordless MFA",
  "00000000-0000-0000-0000-000000000004": "Phishing-resistant MFA",
};

export function previewProposedPolicy(proposed: ProposedCaPolicy, snapshot: TenantSecuritySnapshot): FixGuidePreview {
  if (!proposed.previewable) return { available: false, reason: proposed.previewNote || "This policy's conditions aren't in the synced data." };
  if (!(snapshot.signIns || []).some((e) => e.status === "success" || e.status === "report_only_failed")) return { available: false, reason: "No successful sign-ins have been synced for this tenant yet." };
  if (!snapshot.conditionalAccess?.namedLocations && proposed.body.conditions && JSON.stringify(proposed.body.conditions).includes("Locations")) {
    return { available: false, reason: "Named locations haven't been synced for this tenant yet; re-sync to see the preview." };
  }
  return { available: true, result: previewPolicyImpact(snapshot, mapProposedPolicy(proposed.body), proposed.namedLocation ? [proposed.namedLocation.preview] : []) };
}

// A proposed policy body mapped the way the sync maps a real one: Graph
// returns the strength's name with the policy, and the beta-only session
// controls come from a second read (mapCaBetaSessionExtras).
export function mapProposedPolicy(body: Record<string, unknown>, id = "proposed"): CAPolicyRule {
  const b = body as any;
  const strength = b.grantControls?.authenticationStrength;
  const withNames = strength?.id ? { ...b, grantControls: { ...b.grantControls, authenticationStrength: { ...strength, displayName: strength.displayName || BUILT_IN_STRENGTH_NAMES[strength.id] } } } : b;
  const rule = mapConditionalAccessPolicy({ id, ...withNames });
  const extras = mapCaBetaSessionExtras(b);
  return Object.keys(extras).length > 0 ? { ...rule, sessionControls: { ...(rule.sessionControls || {}), ...extras } } : rule;
}

function resolveCommand(command: GuideCommand | undefined, ctx: FixGuideContext): ResolvedCommand | undefined {
  if (!command) return undefined;
  const shell = SHELL_CONNECT[command.shell];
  return { ...command, shellLabel: shell.label, install: shell.install, connect: shell.connect({ tenantId: ctx.tenantId, graphScopes: command.graphScopes, sharePointAdminUrl: ctx.sharePointAdminUrl }) };
}

export function buildFixGuide(guideId: string, snapshot: TenantSecuritySnapshot): ResolvedFixGuide | undefined {
  const def = getFixGuideDefinition(guideId);
  if (!def) return undefined;
  const ctx = buildFixGuideContext(guideId, snapshot);
  const { steps, verify, undo, missing, proposedPolicy, ...rest } = def;
  const warnings = [...(missing?.(ctx) || [])];
  const shells = def.steps(ctx).map((s) => s.command?.shell);
  if (!ctx.tenantId && (shells.includes("MicrosoftGraph") || shells.includes("MicrosoftGraphBeta"))) warnings.push("This tenant's ID isn't known here; replace <tenant ID> in the connect line.");
  if (!ctx.sharePointAdminUrl && shells.includes("SharePointOnline")) warnings.push("This tenant's SharePoint admin address isn't known here; replace <tenant> in the connect line (it's the part before .sharepoint.com).");
  return {
    ...rest,
    tenantName: ctx.tenantName,
    preview: proposedPolicy ? previewProposedPolicy(proposedPolicy(ctx), snapshot) : undefined,
    steps: steps(ctx).map((s) => ({
      ...s,
      // SharePoint guides start at the generic admin link; use this tenant's own admin center when known.
      portal: s.portal && s.portal.url === SHAREPOINT_ADMIN_PLACEHOLDER && ctx.sharePointAdminUrl ? { ...s.portal, url: ctx.sharePointAdminUrl } : s.portal,
      command: resolveCommand(s.command, ctx),
    })),
    verify: { inClarity: verify.inClarity, command: resolveCommand(verify.command, ctx) },
    undo: { text: undo.text, command: resolveCommand(undo.command, ctx) },
    warnings,
  };
}
