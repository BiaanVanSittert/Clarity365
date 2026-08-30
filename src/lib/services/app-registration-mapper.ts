import { AppRegistrationItem } from "../types";

// Common Microsoft Graph well-known permission IDs to human-readable names mapping
export const WELL_KNOWN_GRAPH_PERMISSIONS: Record<string, string> = {
  // RoleManagement / Directory / Application
  "9e3f62cf-ca93-4989-b6ce-bf83e28f9fe8": "RoleManagement.ReadWrite.Directory",
  "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
  "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
  "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
  "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
  "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
  "df021288-bdef-4463-88db-d42042e6e8c4": "User.Read.All",
  "62a82d11-2ee6-4e76-ba0b-3a2009a40066": "Group.ReadWrite.All",
  // Mail
  "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
  "024d486e-b451-40c0-abe7-d356e4713e01": "Mail.ReadWrite.All",
  "570265a9-bc06-444b-8640-2dd786b229bc": "Mail.Send",
  "810c84a8-4a9e-49e6-bf7d-12d183f40d04": "Mail.Read",
  // Files
  "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
  "01d48897-4a99-4734-a808-724a04ca79dc": "Files.Read.All",
  // Security / Audit
  "dbb22700-a775-437c-85ea-6154ec816699": "AuditLog.Read.All",
  "84739192-36c1-4475-8eb6-042861214e4b": "SecurityEvents.Read.All",
};

export const HIGH_PRIVILEGE_PERMISSIONS = new Set([
  "RoleManagement.ReadWrite.Directory",
  "Directory.ReadWrite.All",
  "Application.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "Mail.ReadWrite",
  "Mail.ReadWrite.All",
  "Mail.Send",
  "User.ReadWrite.All",
  "Group.ReadWrite.All",
  "Files.ReadWrite.All",
  "AuditLog.Read.All",
  "SecurityEvents.Read.All",
]);

export function mapAppRegistration(raw: any): AppRegistrationItem {
  const passwordCredentials = Array.isArray(raw.passwordCredentials) ? raw.passwordCredentials : [];
  const keyCredentials = Array.isArray(raw.keyCredentials) ? raw.keyCredentials : [];

  const now = Date.now();
  const thirtyDaysMs = 30 * 86_400_000;

  const isExpiring = (endDateTime?: string) => {
    if (!endDateTime) return false;
    const expiry = new Date(endDateTime).getTime();
    return !isNaN(expiry) && expiry <= now + thirtyDaysMs;
  };

  const expiringSecrets = passwordCredentials.filter((c: any) => isExpiring(c.endDateTime)).length;
  const expiringCerts = keyCredentials.filter((c: any) => isExpiring(c.endDateTime)).length;
  const expiringCredentialsCount = expiringSecrets + expiringCerts;

  // Extract permissions from requiredResourceAccess
  const allPermissions: string[] = [];
  if (Array.isArray(raw.requiredResourceAccess)) {
    raw.requiredResourceAccess.forEach((res: any) => {
      if (Array.isArray(res.resourceAccess)) {
        res.resourceAccess.forEach((ra: any) => {
          const knownName = WELL_KNOWN_GRAPH_PERMISSIONS[ra.id];
          if (knownName) {
            allPermissions.push(knownName);
          } else if (ra.id) {
            allPermissions.push(`Scope:${ra.id}`);
          }
        });
      }
    });
  }

  // Also extract permissions if raw already contains explicit strings (e.g. from service principal grants)
  if (Array.isArray(raw.allPermissions)) {
    raw.allPermissions.forEach((p: string) => {
      if (!allPermissions.includes(p)) allPermissions.push(p);
    });
  }

  const highPrivilegePermissions = allPermissions.filter((p) => HIGH_PRIVILEGE_PERMISSIONS.has(p));

  const publisher = raw.publisherDomain || raw.publisherName || raw.publisher || "Unknown (Unverified Publisher)";
  const isMicrosoftApp =
    typeof raw.isMicrosoftApp === "boolean"
      ? raw.isMicrosoftApp
      : publisher.toLowerCase().includes("microsoft") ||
        (raw.publisherDomain && raw.publisherDomain.toLowerCase().endsWith(".microsoft.com")) ||
        false;

  const isMultiTenant =
    typeof raw.isMultiTenant === "boolean"
      ? raw.isMultiTenant
      : raw.signInAudience
      ? raw.signInAudience.includes("MultipleOrgs") || raw.signInAudience.includes("Personal")
      : false;

  // Risk Classification
  let riskCategory: AppRegistrationItem["riskCategory"] = "low";
  if (
    highPrivilegePermissions.some(
      (p) =>
        p === "Directory.ReadWrite.All" ||
        p === "RoleManagement.ReadWrite.Directory" ||
        p === "Mail.ReadWrite.All" ||
        p === "Application.ReadWrite.All"
    ) ||
    (highPrivilegePermissions.length > 0 && expiringCredentialsCount > 0)
  ) {
    riskCategory = "critical";
  } else if (highPrivilegePermissions.length > 0 || expiringCredentialsCount > 0) {
    riskCategory = "high";
  } else if (passwordCredentials.length > 0 || isMultiTenant) {
    riskCategory = "moderate";
  }

  return {
    id: raw.id || raw.appId || "unknown-id",
    appId: raw.appId || raw.id || "00000000-0000-0000-0000-000000000000",
    displayName: raw.displayName || "Unnamed Application",
    publisher,
    isMicrosoftApp,
    isMultiTenant,
    createdDateTime: raw.createdDateTime || new Date().toISOString(),
    secretsCount: passwordCredentials.length,
    certificatesCount: keyCredentials.length,
    expiringCredentialsCount,
    highPrivilegePermissions,
    allPermissions,
    riskCategory,
  };
}
