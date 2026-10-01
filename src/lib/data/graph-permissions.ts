// The one list of Microsoft Graph application permissions Clarity365 uses.
// Onboarding (AddTenantModal), the Permissions check
// (testAppRegistrationPermissions in graph-client.ts) and the sync's error
// handling (sync-permission-errors.ts) all read this, so they can't drift
// apart - which is how every live tenant ended up permanently "degraded":
// two permissions the sync needed were in neither of the two older lists.
// Client-safe: plain data, no server imports.
//
// Ordered read-only first, optional last (write-capable last of all). Every
// required permission is read-only; the optional ones each unlock one extra
// feature and declining them never shows as a problem.
export interface GraphPermissionDefinition {
  // Display name. A few rows list two permissions Microsoft accepts for the
  // same call ("A / B") - granted if either is present.
  permission: string;
  // The exact name(s) to add under API permissions in Entra.
  grant: string[];
  // Prefixes of the sync errors (graph-client.ts's syncErrors.push) for the
  // sync steps this permission unlocks.
  syncSteps?: string[];
  // Optional permissions only: one short line for the onboarding checklist.
  purpose?: string;
  scope: "Application";
  description: string;
  endpoint: string;
  method?: "GET" | "POST";
  body?: string;
  requiredFor: string;
  isWriteAccess?: boolean;
  optional?: boolean;
}

export const GRAPH_PERMISSIONS: GraphPermissionDefinition[] = [
  {
    permission: "Policy.Read.All",
    grant: ["Policy.Read.All"],
    syncSteps: ["Conditional Access policies", "Named locations"],
    scope: "Application",
    description: "Read Conditional Access policies and tenant identity security baselines.",
    endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    requiredFor: "Module 1: Conditional Access Policy Scanner & Baseline Audit",
  },
  {
    permission: "User.Read.All",
    grant: ["User.Read.All"],
    syncSteps: ["Users"],
    scope: "Application",
    description: "Read user profiles, accountEnabled states, and license assignments.",
    endpoint: "https://graph.microsoft.com/v1.0/users?$top=5&$select=id,displayName,userPrincipalName,accountEnabled",
    requiredFor: "Module 4 & 5: MFA Audit & User Lifecycle Classification",
  },
  {
    permission: "AuditLog.Read.All",
    grant: ["AuditLog.Read.All"],
    syncSteps: ["Sign-in logs"],
    scope: "Application",
    description: "Read Entra ID interactive & non-interactive sign-in logs and diagnostic results.",
    endpoint: "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=5",
    requiredFor: "Module 2: Sign-In Logs & CA Diagnostic Engine",
  },
  {
    permission: "Reports.Read.All / UserAuthenticationMethod.Read.All",
    grant: ["Reports.Read.All", "UserAuthenticationMethod.Read.All"],
    syncSteps: ["MFA registration details"],
    scope: "Application",
    description: "Read user authentication method registration details and MFA enrollment status.",
    endpoint: "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=5",
    requiredFor: "Module 4: MFA Enforcement & Authentication Method Audit",
  },
  {
    permission: "Organization.Read.All / Directory.Read.All",
    grant: ["Organization.Read.All"],
    syncSteps: ["Tenant Licenses"],
    scope: "Application",
    description: "Read tenant SKU subscriptions, license tiers (e.g. Entra ID P2), and verified domains.",
    endpoint: "https://graph.microsoft.com/v1.0/organization",
    requiredFor: "Tenant Capability Detection & License SKU Matrix",
  },
  {
    permission: "RoleManagement.Read.Directory",
    grant: ["RoleManagement.Read.Directory"],
    syncSteps: ["Directory roles", "Privileged role assignments"],
    scope: "Application",
    description: "Read directory role assignments (Global Admin, Security Admin, etc.) to identify privileged accounts.",
    // directoryRoles does not support $top/paging - Graph returns HTTP 400
    // ("This resource does not support custom page sizes") if it's passed,
    // regardless of whether the permission is actually granted.
    endpoint: "https://graph.microsoft.com/v1.0/directoryRoles",
    requiredFor: "Module 6: Privileged Admin Role Assignment & Unprotected Admin Detection",
  },
  {
    permission: "DeviceManagementManagedDevices.Read.All",
    grant: ["DeviceManagementManagedDevices.Read.All"],
    syncSteps: ["Intune devices"],
    scope: "Application",
    description: "Read Intune-managed device inventory, compliance state, and encryption status.",
    endpoint: "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
    requiredFor: "Module 10: Intune Endpoint Security",
  },
  {
    permission: "DeviceManagementConfiguration.Read.All",
    grant: ["DeviceManagementConfiguration.Read.All"],
    syncSteps: ["Intune Endpoint Security policies", "ASR Rules"],
    scope: "Application",
    description:
      "Read Intune Endpoint Security policy assignments (antivirus, EDR) and Attack Surface Reduction rule configuration - the Settings Catalog, classic Device Configuration profiles, and Endpoint Security Template policies that can each configure ASR rules all share this one permission, so granting it once covers all three.",
    endpoint: "https://graph.microsoft.com/beta/deviceManagement/intents?$top=1",
    requiredFor: "Module 10: Intune Endpoint Security (antivirus/EDR policy counts) & ASR Rules (live configuration state)",
  },
  {
    permission: "SecurityEvents.Read.All",
    grant: ["SecurityEvents.Read.All"],
    syncSteps: ["Secure Score"],
    scope: "Application",
    description: "Read Microsoft Secure Score, control profiles, and improvement action recommendations.",
    endpoint: "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
    requiredFor: "Module 3: Defender Secure Score & Historical Timeline",
  },
  {
    permission: "SecurityAlert.Read.All",
    grant: ["SecurityAlert.Read.All"],
    syncSteps: ["MDO Threat Alerts"],
    scope: "Application",
    description: "Read Microsoft Defender for Office 365 threat detections (phishing, malware) from the Security Alerts API.",
    endpoint: "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1",
    requiredFor: "Module 8: MDO Threat Detections",
  },
  {
    permission: "Group.Read.All",
    grant: ["Group.Read.All"],
    syncSteps: ["Groups", "Group Settings"],
    scope: "Application",
    description: "Read Microsoft 365 groups, security groups, and distribution lists - membership, owners, and tenant-wide group settings.",
    endpoint: "https://graph.microsoft.com/v1.0/groups?$top=1",
    requiredFor: "Module 11: Groups & Distribution Management",
  },
  {
    permission: "Sites.Read.All",
    grant: ["Sites.Read.All"],
    syncSteps: ["SharePoint Sites"],
    scope: "Application",
    description: "Read SharePoint site collections and OneDrive storage quotas.",
    endpoint: "https://graph.microsoft.com/v1.0/sites?search=*&$top=1",
    requiredFor: "Module 12: SharePoint & OneDrive Storage (site inventory)",
  },
  {
    permission: "SharePointTenantSettings.Read.All",
    grant: ["SharePointTenantSettings.Read.All"],
    syncSteps: ["SharePoint Settings"],
    scope: "Application",
    description: "Read tenant-wide SharePoint sharing settings (sharing capability ceiling, default link type, anonymous link expiration) - a separate, narrower permission from Sites.Read.All that Microsoft requires specifically for the admin settings API.",
    endpoint: "https://graph.microsoft.com/v1.0/admin/sharepoint/settings",
    requiredFor: "Module 12: SharePoint & OneDrive Storage (tenant-wide policy)",
  },
  {
    permission: "Application.Read.All",
    grant: ["Application.Read.All"],
    syncSteps: ["App Registrations"],
    scope: "Application",
    description: "Read app registrations and their secrets/certificates (expiry dates, requested permissions). Also lets CA05 be deployed, since that policy targets one specific application.",
    endpoint: "https://graph.microsoft.com/v1.0/applications?$top=1&$select=id",
    requiredFor: "Module 9: App Registrations & Connected Services",
  },
  {
    permission: "SecurityIncident.Read.All",
    grant: ["SecurityIncident.Read.All"],
    syncSteps: ["Security Incidents"],
    scope: "Application",
    description: "Read Microsoft Defender XDR incidents and the alerts grouped under them.",
    endpoint: "https://graph.microsoft.com/v1.0/security/incidents?$top=1",
    requiredFor: "Module 8.6: Event Response (incidents)",
  },
  {
    permission: "DeviceManagementServiceConfig.Read.All",
    grant: ["DeviceManagementServiceConfig.Read.All"],
    syncSteps: ["MDE connector settings"],
    scope: "Application",
    description: "Read the Intune ↔ Defender for Endpoint connector settings. A separate permission from DeviceManagementConfiguration.Read.All; Microsoft requires this one for the connector.",
    endpoint: "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors",
    requiredFor: "Module 10: Defender Configuration & Onboarding (connector settings)",
  },
  {
    permission: "ThreatHunting.Read.All",
    grant: ["ThreatHunting.Read.All"],
    purpose: "ASR rule detection activity (needs Defender for Endpoint P2).",
    scope: "Application",
    description:
      "Optional - read live Microsoft Defender for Endpoint Advanced Hunting telemetry (the DeviceEvents table) to show ASR rule detection activity (30-day hit counts and event detail). A materially more restrictive, separately-consented permission than anything else Clarity365 requests. The actual detection-activity query additionally needs a Defender for Endpoint P1/P2 (or equivalent) license for the DeviceEvents table specifically - Defender for Business tenants may have this permission granted yet still see 'table not found' on that one query, which is a license/table-availability gap, not a missing-permission one; without either, ASR rule configuration reporting (which rule is Block/Audit/Warn/Not Configured) still works fully - only the event-count badges and event list are unavailable.",
    endpoint: "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
    method: "POST",
    // Deliberately NOT a DeviceEvents query (unlike the real detection
    // queries below) - a live bug report showed a tenant with
    // ThreatHunting.Read.All genuinely granted still failing this
    // self-test, because DeviceEvents itself doesn't resolve on that
    // tenant's Defender plan (a 400 "table not found", not a 401/403).
    // This probe is a table-independent Kusto literal (`print`, no `from`
    // clause) so the self-test result reflects ONLY whether the
    // permission itself is granted, never a downstream license/table gap.
    body: JSON.stringify({ Query: "print ClarityPermissionProbe = 1", Timespan: "P1D" }),
    requiredFor: "Optional: ASR Rules detection activity (event counts and event detail)",
    optional: true,
  },
  {
    permission: "DelegatedPermissionGrant.Read.All / Directory.Read.All",
    grant: ["DelegatedPermissionGrant.Read.All"],
    syncSteps: ["OAuth consent grants"],
    purpose: "the OAuth app consent check in Security Scenarios.",
    scope: "Application",
    description:
      "Optional - read which apps users and admins have consented to (oauth2PermissionGrants) and with which delegated permissions, for the Security Simulations \"malicious OAuth app consent\" scenario. DelegatedPermissionGrant.Read.All is the least-privileged choice; Directory.Read.All also covers it. Without either, that one check shows as not assessed.",
    endpoint: "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=1",
    requiredFor: "Optional: Security Simulations - OAuth app consent scenario",
    optional: true,
  },
  {
    permission: "Policy.ReadWrite.ConditionalAccess",
    grant: ["Policy.ReadWrite.ConditionalAccess"],
    purpose: "deploy CA baseline policies from Clarity365.",
    scope: "Application",
    description:
      "Optional - only needed to auto-deploy CA baseline policies directly from Clarity365. Without it, Policy.Read.All above still gives full audit/reporting coverage, and Clarity365 generates a PowerShell script you can run manually instead. One baseline, CA05, also needs Application.Read.All granted alongside this (it references a specific application by ID rather than \"All\") - if a CA05 deploy specifically fails while every other baseline works, that's why; the deploy attempt itself will say so.",
    endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
    requiredFor: "Optional: Direct In-App CA Auto-Deployment & Baseline Remediation",
    isWriteAccess: true,
    optional: true,
  },
  {
    permission: "DeviceManagementConfiguration.ReadWrite.All",
    grant: ["DeviceManagementConfiguration.ReadWrite.All"],
    purpose: "deploy Defender, EDR and ASR policies from Clarity365.",
    scope: "Application",
    description:
      "Optional - only needed for Endpoint Security's write-enabled deploy actions (MDE connector setting changes, Defender Antivirus policy deployment, ASR rule deployment). Also gated by a separate per-tenant toggle in the Defender Config module itself (endpointSecurityWriteMode) - both must be turned on before any Deploy button appears. Without it, DeviceManagementConfiguration.Read.All above still gives full read-only reporting, and every deploy screen offers a copy-pasteable PowerShell/portal equivalent instead.",
    endpoint: "https://graph.microsoft.com/beta/deviceManagement/intents?$top=1",
    requiredFor: "Optional: Endpoint Security write-enabled deployment (MDE connector, Defender AV policy, ASR rules)",
    isWriteAccess: true,
    optional: true,
  },
];

export const REQUIRED_GRAPH_PERMISSIONS = GRAPH_PERMISSIONS.filter((p) => !p.optional);
export const OPTIONAL_GRAPH_PERMISSIONS = GRAPH_PERMISSIONS.filter((p) => p.optional);

// Names to add in Entra for a working tenant, in catalogue order.
export const REQUIRED_GRAPH_PERMISSION_NAMES = REQUIRED_GRAPH_PERMISSIONS.flatMap((p) => p.grant);

// Granted if any of a row's alternatives ("A / B") is in the token's roles.
export function isPermissionGrantedByRoles(permissionField: string, grantedRoles: string[]): boolean {
  return permissionField.split("/").some((candidate) => grantedRoles.includes(candidate.trim()));
}

// The permission whose sync step produced this error, matched on the
// "<step>: ..." / "<step> (...): ..." prefix the sync writes.
export function findPermissionForSyncError(error: string): GraphPermissionDefinition | undefined {
  return GRAPH_PERMISSIONS.find((p) => (p.syncSteps || []).some((step) => error.startsWith(`${step}:`) || error.startsWith(`${step} (`)));
}
