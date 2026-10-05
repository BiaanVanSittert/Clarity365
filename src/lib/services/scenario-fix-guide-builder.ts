import { TenantSecuritySnapshot } from "../types";
import {
  FixGuideBreakGlass,
  FixGuideContext,
  FixGuideDefinition,
  FixGuideItem,
  FixGuideStep,
  GuideCommand,
  SHELL_CONNECT,
  getFixGuideDefinition,
} from "../data/scenario-fix-guides";
import { detectLikelyBreakGlassAccounts } from "./ca-sim-context";
import { getRoleTemplateById } from "../utils/directory-role-templates";

// Turns a guide definition into the guide for ONE tenant: commands carry
// that tenant's real object ids and break-glass accounts, and anything that
// couldn't be filled in is listed as a warning. Pure.

export interface ResolvedCommand extends GuideCommand {
  // The connect line for this shell, with the scopes this command needs.
  connect: string;
  install: string;
  shellLabel: string;
}

export interface ResolvedFixGuideStep extends Omit<FixGuideStep, "command"> {
  command?: ResolvedCommand;
}

export interface ResolvedFixGuide extends Omit<FixGuideDefinition, "steps" | "verify" | "undo" | "missing"> {
  tenantName: string;
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

// Which offending items each guide works on.
const ITEM_SOURCES: Record<string, (snapshot: TenantSecuritySnapshot) => FixGuideItem[]> = {
  "remove-guest-admin-roles": guestRoleItems,
};

export function buildFixGuideContext(guideId: string, snapshot: TenantSecuritySnapshot): FixGuideContext {
  return {
    tenantName: snapshot.tenant.displayName,
    tenantId: snapshot.tenant.credentials?.tenantId || undefined,
    breakGlass: breakGlassAccounts(snapshot),
    items: ITEM_SOURCES[guideId]?.(snapshot) || [],
  };
}

function resolveCommand(command: GuideCommand | undefined, ctx: FixGuideContext): ResolvedCommand | undefined {
  if (!command) return undefined;
  const shell = SHELL_CONNECT[command.shell];
  return { ...command, shellLabel: shell.label, install: shell.install, connect: shell.connect({ tenantId: ctx.tenantId, graphScopes: command.graphScopes }) };
}

export function buildFixGuide(guideId: string, snapshot: TenantSecuritySnapshot): ResolvedFixGuide | undefined {
  const def = getFixGuideDefinition(guideId);
  if (!def) return undefined;
  const ctx = buildFixGuideContext(guideId, snapshot);
  const { steps, verify, undo, missing, ...rest } = def;
  const warnings = [...(missing?.(ctx) || [])];
  if (!ctx.tenantId && def.steps(ctx).some((s) => s.command?.shell === "MicrosoftGraph")) warnings.push("This tenant's ID isn't known here; replace <tenant ID> in the connect line.");
  return {
    ...rest,
    tenantName: ctx.tenantName,
    steps: steps(ctx).map((s) => ({ ...s, command: resolveCommand(s.command, ctx) })),
    verify: { inClarity: verify.inClarity, command: resolveCommand(verify.command, ctx) },
    undo: { text: undo.text, command: resolveCommand(undo.command, ctx) },
    warnings,
  };
}
