import {
  CasMailboxProtocols,
  OAuthConsentGrant,
  PrivilegedRoleAssignment,
  SharePointTenantPolicy,
} from "../types";

// Pure mappers for the data Security Simulations Stage 5 adds to the sync
// (ai-context-vault/Optimization/Security Simulations Plan.md): SharePoint
// sharing/sync settings, Exchange audit + protocol settings, PIM role
// assignments and OAuth consent grants. Imports only ../types, like every
// file in ai-context-vault/Services/Data Mappers.md.

// ------------------------------------------------------------ SharePoint

// The admin/sharepoint/settings fields beyond the sharing level. Every field
// is only set when Graph actually returned it (typeof check), so a missing
// field stays undefined ("not synced") rather than becoming false.
export function mapSharePointSecuritySettings(raw: any): Pick<
  SharePointTenantPolicy,
  | "linkDefaultsReported"
  | "resharingByExternalUsersEnabled"
  | "unmanagedSyncAppRestricted"
  | "syncAllowedDomainCount"
  | "sharingDomainRestrictionMode"
  | "legacyAuthProtocolsEnabled"
  | "idleSessionSignOutEnabled"
  | "requireAcceptingUserToMatchInvitedUser"
> {
  const out: ReturnType<typeof mapSharePointSecuritySettings> = {
    // v1.0 has neither field; sharepoint-mapper.ts's mapTenantSharingSettings
    // falls back to placeholders when they're absent.
    linkDefaultsReported: raw?.sharingLinkDefaultType !== undefined || raw?.anonymousLinkExpirationRestrictionDays !== undefined,
  };
  if (typeof raw?.isResharingByExternalUsersEnabled === "boolean") out.resharingByExternalUsersEnabled = raw.isResharingByExternalUsersEnabled;
  if (typeof raw?.isUnmanagedSyncAppForTenantRestricted === "boolean") out.unmanagedSyncAppRestricted = raw.isUnmanagedSyncAppForTenantRestricted;
  if (Array.isArray(raw?.allowedDomainGuidsForSyncApp)) out.syncAllowedDomainCount = raw.allowedDomainGuidsForSyncApp.length;
  if (raw?.sharingDomainRestrictionMode === "none" || raw?.sharingDomainRestrictionMode === "allowList" || raw?.sharingDomainRestrictionMode === "blockList") {
    out.sharingDomainRestrictionMode = raw.sharingDomainRestrictionMode;
  }
  if (typeof raw?.isLegacyAuthProtocolsEnabled === "boolean") out.legacyAuthProtocolsEnabled = raw.isLegacyAuthProtocolsEnabled;
  if (typeof raw?.idleSessionSignOut?.isEnabled === "boolean") out.idleSessionSignOutEnabled = raw.idleSessionSignOut.isEnabled;
  if (typeof raw?.isRequireAcceptingUserToMatchInvitedUserEnabled === "boolean") {
    out.requireAcceptingUserToMatchInvitedUser = raw.isRequireAcceptingUserToMatchInvitedUserEnabled;
  }
  return out;
}

// -------------------------------------------------------------- Exchange

// Get-AdminAuditLogConfig / Get-TransportConfig return one object; the
// InvokeCommand wrapper hands back items[0]. Undefined when absent.
export function readBooleanSetting(raw: any, property: string): boolean | undefined {
  const value = raw?.[property];
  if (typeof value === "boolean") return value;
  if (value === "True" || value === "true") return true;
  if (value === "False" || value === "false") return false;
  return undefined;
}

export function mapCasMailbox(raw: any): CasMailboxProtocols | null {
  const address = raw?.PrimarySmtpAddress || raw?.Identity || raw?.Name;
  if (!address) return null;
  const override = readBooleanSetting(raw, "SmtpClientAuthenticationDisabled");
  return {
    primarySmtpAddress: String(address),
    popEnabled: readBooleanSetting(raw, "PopEnabled") ?? false,
    imapEnabled: readBooleanSetting(raw, "ImapEnabled") ?? false,
    activeSyncEnabled: readBooleanSetting(raw, "ActiveSyncEnabled") ?? false,
    smtpClientAuthDisabled: override === undefined ? null : override,
  };
}

// Mailboxes that can use SMTP AUTH: an explicit per-mailbox "enabled"
// override, or no override while the org default leaves it enabled.
export function smtpAuthEnabledFor(mailbox: CasMailboxProtocols, orgWideDisabled: boolean | undefined): boolean | undefined {
  if (mailbox.smtpClientAuthDisabled !== null) return !mailbox.smtpClientAuthDisabled;
  return orgWideDisabled === undefined ? undefined : !orgWideDisabled;
}

// ------------------------------------------------------------------- PIM

function principalOf(raw: any): Pick<PrivilegedRoleAssignment, "principalType" | "principalDisplayName" | "principalUserPrincipalName"> {
  const p = raw?.principal;
  const type = String(p?.["@odata.type"] || "").toLowerCase();
  return {
    principalType: type.endsWith(".user") ? "user" : type.endsWith(".group") ? "group" : type.endsWith(".serviceprincipal") ? "servicePrincipal" : "unknown",
    principalDisplayName: p?.displayName || undefined,
    principalUserPrincipalName: p?.userPrincipalName || undefined,
  };
}

// Only tenant-wide ("/") assignments count as holding the role; an
// administrative-unit-scoped assignment isn't a tenant-wide admin.
const isTenantWide = (raw: any) => !raw?.directoryScopeId || raw.directoryScopeId === "/";

export function mapPimAssignments(eligibleRaw: any[], activeRaw: any[]): PrivilegedRoleAssignment[] {
  const out: PrivilegedRoleAssignment[] = [];
  for (const raw of eligibleRaw) {
    if (!raw?.principalId || !raw?.roleDefinitionId || !isTenantWide(raw)) continue;
    out.push({
      principalId: raw.principalId,
      roleTemplateId: String(raw.roleDefinitionId).toLowerCase(),
      kind: "eligible",
      endDateTime: raw.endDateTime || undefined,
      ...principalOf(raw),
    });
  }
  for (const raw of activeRaw) {
    if (!raw?.principalId || !raw?.roleDefinitionId || !isTenantWide(raw)) continue;
    const activated = String(raw.assignmentType || "").toLowerCase() === "activated";
    out.push({
      principalId: raw.principalId,
      roleTemplateId: String(raw.roleDefinitionId).toLowerCase(),
      kind: activated ? "activated" : raw.endDateTime ? "activeTimeBound" : "activePermanent",
      endDateTime: raw.endDateTime || undefined,
      ...principalOf(raw),
    });
  }
  return out;
}

// Non-PIM fallback (/roleManagement/directory/roleAssignments): active
// assignments only, with no schedule - every entry reads as permanent.
export function mapRoleAssignmentsFallback(raw: any[]): PrivilegedRoleAssignment[] {
  return raw
    .filter((r) => r?.principalId && r?.roleDefinitionId && isTenantWide(r))
    .map((r) => ({
      principalId: r.principalId,
      roleTemplateId: String(r.roleDefinitionId).toLowerCase(),
      kind: "activePermanent" as const,
      ...principalOf(r),
    }));
}

// ---------------------------------------------------------- OAuth grants

// Delegated scopes that give an app broad reach into mail, files or the
// directory - the ones a consent-phishing app asks for.
export const HIGH_RISK_DELEGATED_SCOPES = new Set(
  [
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
    "Mail.Read.Shared",
    "Mail.ReadWrite.Shared",
    "MailboxSettings.ReadWrite",
    "Files.Read.All",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
    "Contacts.Read",
    "Contacts.ReadWrite",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "EWS.AccessAsUser.All",
    "full_access_as_user",
    "Notes.ReadWrite.All",
  ].map((s) => s.toLowerCase())
);

// Microsoft's own app-owner tenants (first-party apps).
const MICROSOFT_OWNER_TENANTS = new Set(["f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"]);

export interface ServicePrincipalInfo {
  displayName?: string;
  publisherName?: string;
  verifiedPublisher?: { displayName?: string | null } | null;
  appOwnerOrganizationId?: string | null;
}

// Aggregates raw oauth2PermissionGrants into one row per app + consent type,
// with the union of scopes and the number of consenting users.
export function aggregateOAuthGrants(rawGrants: any[], servicePrincipals: Map<string, ServicePrincipalInfo>): OAuthConsentGrant[] {
  const byKey = new Map<string, { clientId: string; consentType: "AllPrincipals" | "Principal"; scopes: Set<string>; users: Set<string> }>();
  for (const g of rawGrants) {
    if (!g?.clientId) continue;
    const consentType = g.consentType === "AllPrincipals" ? "AllPrincipals" : "Principal";
    const key = `${g.clientId}|${consentType}`;
    const entry = byKey.get(key) || { clientId: g.clientId, consentType, scopes: new Set<string>(), users: new Set<string>() };
    String(g.scope || "")
      .split(" ")
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((s) => entry.scopes.add(s));
    if (consentType === "Principal" && g.principalId) entry.users.add(g.principalId);
    byKey.set(key, entry);
  }

  return [...byKey.values()].map((e) => {
    const sp = servicePrincipals.get(e.clientId);
    const scopes = [...e.scopes].sort();
    return {
      servicePrincipalId: e.clientId,
      appDisplayName: sp?.displayName,
      publisherName: sp?.publisherName,
      publisherVerified: sp ? !!sp.verifiedPublisher?.displayName : undefined,
      isMicrosoftApp: sp?.appOwnerOrganizationId ? MICROSOFT_OWNER_TENANTS.has(sp.appOwnerOrganizationId.toLowerCase()) : undefined,
      consentType: e.consentType,
      scopes,
      highRiskScopes: scopes.filter((s) => HIGH_RISK_DELEGATED_SCOPES.has(s.toLowerCase())),
      userCount: e.users.size,
    };
  });
}
