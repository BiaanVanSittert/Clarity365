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
import { detectLikelyBreakGlassAccounts } from "./ca-sim-context";
import { getRoleTemplateById } from "../utils/directory-role-templates";
import { smtpAuthEnabledFor } from "./security-posture-mapper";
import { mapConditionalAccessPolicy } from "./ca-policy-mapper";
import { mapCaBetaSessionExtras } from "./ca-environment-mapper";
import { PolicyImpactPreview, previewPolicyImpact } from "./ca-policy-impact";
import { normalizeCountryCode, UNKNOWN_COUNTRY } from "../utils/sign-in-country";

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

// Which offending items each guide works on.
const ITEM_SOURCES: Record<string, (snapshot: TenantSecuritySnapshot) => FixGuideItem[]> = {
  "remove-guest-admin-roles": guestRoleItems,
  "restrict-smtp-auth-mailboxes": smtpAuthMailboxItems,
  "disable-pop-imap": popImapMailboxItems,
  "sharepoint-restrict-anyone-sites": anyoneSiteItems,
  "include-unknown-countries": unknownCountryLocationItems,
  "keep-cae-on": caeDisabledPolicyItems,
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
