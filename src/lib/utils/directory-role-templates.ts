// The ONE bridge between the three ways this codebase refers to a Microsoft
// Entra directory role:
//   1. Conditional Access (live): conditions.users.includeRoles/excludeRoles
//      hold role *template* GUIDs.
//   2. UserMfaProfile.adminRoles: role *display names* ("Global Administrator").
//   3. Demo data and local post-deploy snapshot writes: marker strings in
//      conditions.users.include such as "DirectoryRole:GlobalAdmin" or
//      "AllAdmins" (see mock-tenants.ts, tenant-store.ts deployBaselinePolicy).
// Anything that needs to ask "does this CA policy target this user's role"
// must go through here rather than re-deriving a mapping inline - see the
// duplicated-logic bug class in ai-context-vault/Optimization/Optimization Plan.md.
//
// Template ids are fixed by Microsoft and identical in every tenant.

export interface DirectoryRoleTemplate {
  templateId: string;
  displayName: string;
  // One of the 14 roles Microsoft's "Require MFA for administrators" CA
  // template targets - what "admins" means for persona coverage.
  isPrivileged: boolean;
  // Marker aliases used by demo data / local writes ("GlobalAdmin" in
  // "DirectoryRole:GlobalAdmin"). Compared case-insensitively.
  markerAliases?: string[];
  // Older names Graph or exports may still return.
  legacyNames?: string[];
}

export const DIRECTORY_ROLE_TEMPLATES: DirectoryRoleTemplate[] = [
  { templateId: "62e90394-69f5-4237-9190-012177145e10", displayName: "Global Administrator", isPrivileged: true, markerAliases: ["GlobalAdmin", "GlobalAdministrator"], legacyNames: ["Company Administrator"] },
  { templateId: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", displayName: "Application Administrator", isPrivileged: true, markerAliases: ["ApplicationAdmin"] },
  { templateId: "c4e39bd9-1100-46d3-8c65-fb160da0071f", displayName: "Authentication Administrator", isPrivileged: true, markerAliases: ["AuthenticationAdmin"] },
  { templateId: "b0f54661-2d74-4c50-afa3-1ec803f12efe", displayName: "Billing Administrator", isPrivileged: true, markerAliases: ["BillingAdmin"] },
  { templateId: "158c047a-c907-4556-b7ef-446551a6b5f7", displayName: "Cloud Application Administrator", isPrivileged: true, markerAliases: ["CloudApplicationAdmin", "CloudAppAdmin"] },
  { templateId: "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", displayName: "Conditional Access Administrator", isPrivileged: true, markerAliases: ["ConditionalAccessAdmin"] },
  { templateId: "29232cdf-9323-42fd-ade2-1d097af3e4de", displayName: "Exchange Administrator", isPrivileged: true, markerAliases: ["ExchangeAdmin"] },
  { templateId: "729827e3-9c14-49f7-bb1b-9608f156bbb8", displayName: "Helpdesk Administrator", isPrivileged: true, markerAliases: ["HelpdeskAdmin"] },
  { templateId: "966707d0-3269-4727-9be2-8c3a10f19b9d", displayName: "Password Administrator", isPrivileged: true, markerAliases: ["PasswordAdmin"] },
  { templateId: "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", displayName: "Privileged Authentication Administrator", isPrivileged: true, markerAliases: ["PrivilegedAuthenticationAdmin"] },
  { templateId: "e8611ab8-c189-46e8-94e1-60213ab1f814", displayName: "Privileged Role Administrator", isPrivileged: true, markerAliases: ["PrivilegedRoleAdmin"] },
  { templateId: "194ae4cb-b126-40b2-bd5b-6091b380977d", displayName: "Security Administrator", isPrivileged: true, markerAliases: ["SecurityAdmin"] },
  { templateId: "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", displayName: "SharePoint Administrator", isPrivileged: true, markerAliases: ["SharePointAdmin"] },
  { templateId: "fe930be7-5e62-47db-91af-98c3a49a38b1", displayName: "User Administrator", isPrivileged: true, markerAliases: ["UserAdmin"] },
  // Not in Microsoft's 14-role admin MFA template, but common enough in real
  // tenants to resolve by name.
  { templateId: "17315797-102d-40b4-93e0-432062caca18", displayName: "Compliance Administrator", isPrivileged: false, markerAliases: ["ComplianceAdmin"] },
  { templateId: "f2ef992c-3afb-46b9-b7cf-a126ee74c451", displayName: "Global Reader", isPrivileged: false, markerAliases: ["GlobalReader"] },
  { templateId: "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2", displayName: "Hybrid Identity Administrator", isPrivileged: false, markerAliases: ["HybridIdentityAdmin"] },
  { templateId: "3a2c62db-5318-420d-8d74-23affee5d9d5", displayName: "Intune Administrator", isPrivileged: false, markerAliases: ["IntuneAdmin"] },
  { templateId: "5d6b6bb7-de71-4623-b4af-96380a352509", displayName: "Security Reader", isPrivileged: false, markerAliases: ["SecurityReader"] },
  { templateId: "69091246-20e8-4a56-aa4d-066075b2a7a8", displayName: "Teams Administrator", isPrivileged: false, markerAliases: ["TeamsAdmin"] },
  // The Entra Connect sync account's role - routinely excluded from CA.
  { templateId: "d29b2b05-8046-44ba-8758-1e26182fcf32", displayName: "Directory Synchronization Accounts", isPrivileged: false },
];

export const GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10";

const BY_TEMPLATE_ID = new Map(DIRECTORY_ROLE_TEMPLATES.map((r) => [r.templateId.toLowerCase(), r]));

const BY_NAME = new Map<string, DirectoryRoleTemplate>();
for (const r of DIRECTORY_ROLE_TEMPLATES) {
  BY_NAME.set(r.displayName.toLowerCase(), r);
  for (const legacy of r.legacyNames || []) BY_NAME.set(legacy.toLowerCase(), r);
}

const BY_MARKER = new Map<string, DirectoryRoleTemplate>();
for (const r of DIRECTORY_ROLE_TEMPLATES) {
  for (const alias of r.markerAliases || []) BY_MARKER.set(alias.toLowerCase(), r);
}

export function getRoleTemplateById(templateId: string): DirectoryRoleTemplate | undefined {
  return BY_TEMPLATE_ID.get(templateId.toLowerCase());
}

// Display name -> template (case-insensitive, legacy names accepted).
export function getRoleTemplateByName(displayName: string): DirectoryRoleTemplate | undefined {
  return BY_NAME.get(displayName.trim().toLowerCase());
}

// Resolves one CA users.include/includeRoles entry to the role template ids
// it stands for. Returns [] when the entry is not a role reference at all
// (a user id, "All", "GuestsOrExternalUsers", ...), so callers can use a
// non-empty result as "this entry targets roles".
//   - a template GUID (live includeRoles)            -> [that id]
//   - "DirectoryRole:<Alias>" (demo / local writes)   -> [alias's id]
//   - "AllAdmins" (demo)                              -> every isPrivileged id
export function resolveCaRoleReference(entry: string): string[] {
  const trimmed = entry.trim();
  const byId = BY_TEMPLATE_ID.get(trimmed.toLowerCase());
  if (byId) return [byId.templateId];

  if (trimmed === "AllAdmins") {
    return DIRECTORY_ROLE_TEMPLATES.filter((r) => r.isPrivileged).map((r) => r.templateId);
  }

  const prefix = "directoryrole:";
  if (trimmed.toLowerCase().startsWith(prefix)) {
    const alias = trimmed.slice(prefix.length).toLowerCase();
    const r = BY_MARKER.get(alias) || BY_NAME.get(alias);
    return r ? [r.templateId] : [];
  }

  return [];
}

// UserMfaProfile.adminRoles (display names) -> template ids. Names this map
// doesn't know are dropped, not guessed - callers that must not miss a role
// should compare adminRoles.length against the result's length.
export function roleNamesToTemplateIds(roleNames: string[]): string[] {
  const ids: string[] = [];
  for (const name of roleNames) {
    const r = getRoleTemplateByName(name);
    if (r && !ids.includes(r.templateId)) ids.push(r.templateId);
  }
  return ids;
}

export function isGlobalAdminRoleName(roleName: string): boolean {
  return getRoleTemplateByName(roleName)?.templateId === GLOBAL_ADMIN_TEMPLATE_ID;
}
