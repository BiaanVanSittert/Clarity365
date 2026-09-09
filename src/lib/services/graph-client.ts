import { Tenant, TenantSecuritySnapshot, CAPolicyRule, UserMfaProfile, TenantAccountSummary, SignInEvent, SignInStatus, SyncHealth, IntuneDevice, TenantSecureScore, MdoThreatPolicy, TablEntry, MdoThreatAlert, MailboxItem, EmailForwardingRule, MailflowTransportRule, DomainAuthStatus, MailflowConnector, TenantGroup, SharePointTenantPolicy, AppRegistrationItem, TenantCapability, TenantLicenseSku, SecurityIncidentItem, AsrRuleMode, AsrRuleState, AsrRuleActivitySummary, AsrDetectionEvent } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { classifyPolicyBaselineCode, computeBaselineCoveragePercent } from "./ca-baseline-matcher";
import { fetchAllPages } from "./graph-pagination";
import { createBlankSnapshot } from "../data/default-snapshot";
import { classifyUserAuthMethods } from "./mfa-classifier";
import { mapManagedDeviceToIntuneDevice } from "./intune-mapper";
import { mapSecureScoreControl, buildSecureScoreHistory, computeScoreDelta, extractIndustryBenchmark } from "./secure-score-mapper";
import { fetchMdoPoliciesAndTabl, fetchMailflowData, fetchAcceptedDomainsAndDkim } from "./exo-client";
import { mapMdoAlert } from "./mdo-alert-mapper";
import { checkSpfRecord, checkDmarcRecord } from "./domain-dns-checker";
import {
  mapGroup,
  mapGroupExpirationPolicyEnabled,
  mapGroupSelfServiceCreationRestricted,
  mapGroupNamingPolicyEnabled,
} from "./groups-mapper";
import { mapSharePointSite, mapTenantSharingSettings } from "./sharepoint-mapper";
import { mapAppRegistration } from "./app-registration-mapper";
import { mapSubscribedSkusToCapabilities } from "./capabilities-mapper";
import { mapSecurityIncident, synthesizeIncidentsFromMdoAlerts } from "./incident-mapper";
import { graphFetch } from "./graph-fetch";
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";
import { buildActivitySummaries, synthesizeMockActivity } from "./asr-detection-mapper";
import {
  AsrConfigSignal,
  LEGACY_ASR_PROPERTY_TO_RULE_ID,
  buildAsrSlugMap,
  mapAsrSettingDefinitionIdsToSignals,
  mapNamedPropertyValuesToSignals,
  mergeAsrRuleStates,
} from "./asr-configuration-mapper";



// No bulk "every group's owners/members" Graph endpoint exists - capped for
// the same reason the mailflow mailbox scan is capped (see exo-client.ts).
const MAX_GROUPS_FOR_MEMBER_SCAN = 250;
// No bulk "every site's storage quota" Graph endpoint exists either - capped
// for the same reason.
const MAX_SITES_FOR_STORAGE_SCAN = 250;

interface CachedToken {
  token: string;
  expiresAt: number;
}

interface TokenCacheGlobal {
  clarity365GraphTokenCache?: Map<string, CachedToken>;
}

// Cached per app-registration (Azure tenant ID + client ID), not per Clarity365
// tenant record, since that pair is what actually identifies the credential. Kept
// on globalThis so a Next.js dev-mode hot-reload doesn't spawn a second cache and
// silently double the token-endpoint traffic. A 5-minute safety margin is
// subtracted from the real expiry so a long paginated sync can't start a request
// with a token that expires mid-flight.
const TOKEN_SAFETY_MARGIN_MS = 5 * 60_000;
const tokenCacheGlobal = globalThis as unknown as TokenCacheGlobal;
if (!tokenCacheGlobal.clarity365GraphTokenCache) {
  tokenCacheGlobal.clarity365GraphTokenCache = new Map<string, CachedToken>();
}
const tokenCache = tokenCacheGlobal.clarity365GraphTokenCache;

interface AsrSlugMapCacheGlobal {
  clarity365AsrSlugMapCache?: Map<string, string>;
}

// Microsoft's Settings Catalog metadata for the ASR root setting is global,
// tenant-agnostic catalog data (which rule slugs exist and what they're
// called), not per-tenant state - so it's fetched once per process and
// reused across every tenant in a fleet sync, on the same globalThis
// pattern as tokenCache above, rather than refetched on every single sync.
const asrSlugMapCacheGlobal = globalThis as unknown as AsrSlugMapCacheGlobal;

export interface PermissionTestResult {
  permission: string;
  scope: "Application" | "Delegated";
  description: string;
  endpoint: string;
  // Defaults to GET when omitted. Only a permission with no GET-able Graph
  // surface (e.g. ThreatHunting.Read.All - Advanced Hunting is POST-only)
  // needs this set explicitly.
  method?: "GET" | "POST";
  body?: string;
  status: "granted" | "missing" | "untested";
  statusCode?: number;
  errorMessage?: string;
  requiredFor: string;
  // True only for permissions that let Clarity365 create/modify/delete data in
  // the live tenant, not just read it - flagged distinctly in the Permissions
  // UI so granting it is a conscious choice, not lost among read-only scopes.
  isWriteAccess?: boolean;
  // True for a permission the app doesn't need to function - it unlocks one
  // additional feature (read-only or write-capable) on top of the reporting
  // this app already provides without it. Excluded from the pass/fail rollup
  // in overallStatus so declining it never shows as a problem needing
  // attention - whether that's choosing read-only/reporting-only mode
  // (declining the one write-capable permission) or simply not having the
  // separately-consented, separately-licensed permission Advanced Hunting
  // needs (declining ThreatHunting.Read.All).
  optional?: boolean;
}

export interface TenantPermissionReport {
  tenantId: string;
  tenantName: string;
  testedAt: string;
  overallStatus: "all_granted" | "partial" | "failed";
  permissions: PermissionTestResult[];
}

export async function getGraphAccessToken(credentials: Tenant["credentials"]): Promise<{ token?: string; error?: string }> {
  if (!credentials.tenantId || !credentials.clientId || !credentials.clientSecret) {
    return { error: "Missing Tenant ID, Client ID, or Client Secret in tenant configuration." };
  }

  const cacheKey = `${credentials.tenantId}:${credentials.clientId}`;
  const cached = tokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return { token: cached.token };
  }

  const tokenEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams();
  body.append("client_id", credentials.clientId);
  body.append("client_secret", credentials.clientSecret);
  body.append("scope", "https://graph.microsoft.com/.default");
  body.append("grant_type", "client_credentials");

  try {
    const res = await graphFetch(
      tokenEndpoint,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      },
      { timeoutMs: 10_000 } // fail fast - the whole sync is worthless without a token
    );

    const data = await res.json();
    if (!res.ok || !data.access_token) {
      return { error: data.error_description || data.error || `Authentication failed with status ${res.status}` };
    }

    const expiresInSeconds = typeof data.expires_in === "number" ? data.expires_in : 3600;
    tokenCache.set(cacheKey, {
      token: data.access_token,
      expiresAt: Date.now() + expiresInSeconds * 1000 - TOKEN_SAFETY_MARGIN_MS,
    });
    console.log(`[Graph Client] Acquired new access token for tenant ${credentials.tenantId} (valid ${expiresInSeconds}s).`);

    return { token: data.access_token };
  } catch (err: any) {
    return { error: err.message || "Failed to reach Microsoft Entra ID token endpoint." };
  }
}

export async function testAppRegistrationPermissions(tenant: Tenant): Promise<TenantPermissionReport> {
  // Ordered read-only first, optional last (write-capable last of all) -
  // ThreatHunting.Read.All and Policy.ReadWrite.ConditionalAccess are the
  // only two optional permissions this app ever requests: every other
  // permission below already gives Clarity365 full audit/reporting coverage
  // without either of them (including generating a copy-pasteable PowerShell
  // script for CA baseline gaps in place of the write permission). Granting
  // ThreatHunting.Read.All additionally enables ASR rule detection-activity
  // reporting; granting the CA write permission additionally enables in-app
  // one-click auto-deployment - neither is required for the app to work.
  const permissionsToTest: Omit<PermissionTestResult, "status">[] = [
    {
      permission: "Policy.Read.All",
      scope: "Application",
      description: "Read Conditional Access policies and tenant identity security baselines.",
      endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      requiredFor: "Module 1: Conditional Access Policy Scanner & Baseline Audit",
    },
    {
      permission: "User.Read.All",
      scope: "Application",
      description: "Read user profiles, accountEnabled states, and license assignments.",
      endpoint: "https://graph.microsoft.com/v1.0/users?$top=5&$select=id,displayName,userPrincipalName,accountEnabled",
      requiredFor: "Module 4 & 5: MFA Audit & User Lifecycle Classification",
    },
    {
      permission: "AuditLog.Read.All",
      scope: "Application",
      description: "Read Entra ID interactive & non-interactive sign-in logs and diagnostic results.",
      endpoint: "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=5",
      requiredFor: "Module 2: Sign-In Logs & CA Diagnostic Engine",
    },
    {
      permission: "Reports.Read.All / UserAuthenticationMethod.Read.All",
      scope: "Application",
      description: "Read user authentication method registration details and MFA enrollment status.",
      endpoint: "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=5",
      requiredFor: "Module 4: MFA Enforcement & Authentication Method Audit",
    },
    {
      permission: "Organization.Read.All / Directory.Read.All",
      scope: "Application",
      description: "Read tenant SKU subscriptions, license tiers (e.g. Entra ID P2), and verified domains.",
      endpoint: "https://graph.microsoft.com/v1.0/organization",
      requiredFor: "Tenant Capability Detection & License SKU Matrix",
    },
    {
      permission: "RoleManagement.Read.Directory",
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
      scope: "Application",
      description: "Read Intune-managed device inventory, compliance state, and encryption status.",
      endpoint: "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
      requiredFor: "Module 10: Intune Endpoint Security",
    },
    {
      permission: "DeviceManagementConfiguration.Read.All",
      scope: "Application",
      description:
        "Read Intune Endpoint Security policy assignments (antivirus, EDR) and Attack Surface Reduction rule configuration - the Settings Catalog, classic Device Configuration profiles, and Endpoint Security Template policies that can each configure ASR rules all share this one permission, so granting it once covers all three.",
      endpoint: "https://graph.microsoft.com/beta/deviceManagement/intents?$top=1",
      requiredFor: "Module 10: Intune Endpoint Security (antivirus/EDR policy counts) & ASR Rules (live configuration state)",
    },
    {
      permission: "SecurityEvents.Read.All",
      scope: "Application",
      description: "Read Microsoft Secure Score, control profiles, and improvement action recommendations.",
      endpoint: "https://graph.microsoft.com/v1.0/security/secureScores?$top=1",
      requiredFor: "Module 3: Defender Secure Score & Historical Timeline",
    },
    {
      permission: "SecurityAlert.Read.All",
      scope: "Application",
      description: "Read Microsoft Defender for Office 365 threat detections (phishing, malware) from the Security Alerts API.",
      endpoint: "https://graph.microsoft.com/v1.0/security/alerts_v2?$top=1",
      requiredFor: "Module 8: MDO Threat Detections",
    },
    {
      permission: "Group.Read.All",
      scope: "Application",
      description: "Read Microsoft 365 groups, security groups, and distribution lists - membership, owners, and tenant-wide group settings.",
      endpoint: "https://graph.microsoft.com/v1.0/groups?$top=1",
      requiredFor: "Module 11: Groups & Distribution Management",
    },
    {
      permission: "Sites.Read.All",
      scope: "Application",
      description: "Read SharePoint site collections and OneDrive storage quotas.",
      endpoint: "https://graph.microsoft.com/v1.0/sites?search=*&$top=1",
      requiredFor: "Module 12: SharePoint & OneDrive Storage (site inventory)",
    },
    {
      permission: "SharePointTenantSettings.Read.All",
      scope: "Application",
      description: "Read tenant-wide SharePoint sharing settings (sharing capability ceiling, default link type, anonymous link expiration) - a separate, narrower permission from Sites.Read.All that Microsoft requires specifically for the admin settings API.",
      endpoint: "https://graph.microsoft.com/v1.0/admin/sharepoint/settings",
      requiredFor: "Module 12: SharePoint & OneDrive Storage (tenant-wide policy)",
    },
    {
      permission: "ThreatHunting.Read.All",
      scope: "Application",
      description:
        "Optional - read live Microsoft Defender for Endpoint Advanced Hunting telemetry (the DeviceEvents table) to show ASR rule detection activity (30-day hit counts and event detail). A materially more restrictive, separately-consented permission than anything else Clarity365 requests, and typically also needs a Defender for Endpoint P2 (or equivalent Business Premium) license on top of the Graph permission itself. Without it, ASR rule configuration reporting (which rule is Block/Audit/Warn/Not Configured) still works fully - only the event-count badges and event list are unavailable.",
      endpoint: "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
      method: "POST",
      body: JSON.stringify({ Query: "DeviceEvents | where Timestamp > ago(1d) | take 1", Timespan: "P1D" }),
      requiredFor: "Optional: ASR Rules detection activity (event counts and event detail)",
      optional: true,
    },
    {
      permission: "Policy.ReadWrite.ConditionalAccess",
      scope: "Application",
      description:
        "Optional - only needed to auto-deploy CA baseline policies directly from Clarity365. Without it, Policy.Read.All above still gives full audit/reporting coverage, and Clarity365 generates a PowerShell script you can run manually instead.",
      endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      requiredFor: "Optional: Direct In-App CA Auto-Deployment & Baseline Remediation",
      isWriteAccess: true,
      optional: true,
    },
  ];

  if (tenant.credentials.authMode === "mock") {
    return {
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      testedAt: new Date().toISOString(),
      overallStatus: "all_granted",
      permissions: permissionsToTest.map((p) => ({ ...p, status: "granted", statusCode: 200 })),
    };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return {
      tenantId: tenant.id,
      tenantName: tenant.displayName,
      testedAt: new Date().toISOString(),
      overallStatus: "failed",
      permissions: permissionsToTest.map((p) => ({
        ...p,
        status: "missing",
        errorMessage: error || "Authentication failed before testing permissions.",
      })),
    };
  }

  const results: PermissionTestResult[] = [];
  let allPassed = true;

  for (const perm of permissionsToTest) {
    try {
      const res = await graphFetch(perm.endpoint, {
        method: perm.method || "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          ...(perm.body ? { "Content-Type": "application/json" } : {}),
        },
        body: perm.body,
      });

      if (res.ok) {
        results.push({
          ...perm,
          status: "granted",
          statusCode: res.status,
        });
      } else {
        if (!perm.optional) allPassed = false;
        const errJson = await res.json().catch(() => ({}));
        results.push({
          ...perm,
          status: "missing",
          statusCode: res.status,
          errorMessage: errJson?.error?.message || `Access denied (${res.status} ${res.statusText})`,
        });
      }
    } catch (e: any) {
      if (!perm.optional) allPassed = false;
      results.push({
        ...perm,
        status: "missing",
        errorMessage: e.message || "Network request failed",
      });
    }
  }

  // Optional permissions (currently just Policy.ReadWrite.ConditionalAccess) are
  // excluded from this rollup entirely - declining an optional write permission
  // is a valid, deliberate choice (read-only/reporting mode), not a problem.
  const requiredResults = results.filter((r) => !r.optional);
  return {
    tenantId: tenant.id,
    tenantName: tenant.displayName,
    testedAt: new Date().toISOString(),
    overallStatus: allPassed
      ? "all_granted"
      : requiredResults.some((r) => r.status === "granted")
      ? "partial"
      : "failed",
    permissions: results,
  };
}

export function buildGraphCaPolicyPayload(code: string, domain: string) {
  switch (code) {
    case "CA01":
      return {
        displayName: "CA01: Block legacy authentication",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["exchangeActiveSync", "otherClients"],
        },
        grantControls: { operator: "OR", builtInControls: ["block"] },
      };
    case "CA02":
      return {
        displayName: "CA02: Require multifactor authentication for all users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: ["GuestsOrExternalUsers"] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA03":
      return {
        displayName: "CA03: Require multifactor authentication for admins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: {
            includeRoles: [
              "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
              "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
              "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
              "729827e3-9c14-49f7-bb1b-9608f156bbb8", // Helpdesk Administrator
              "966707d0-3269-4727-9be2-8c3a10f19b9d", // User Administrator
              "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
            ],
            excludeUsers: [],
          },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA04":
      return {
        displayName: "CA04: Require multifactor authentication for guest access",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["GuestsOrExternalUsers"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA05":
      return {
        displayName: "CA05: Require multifactor authentication for Azure management",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["797f3427-79cd-4827-8132-47d473d450e4"] },
          clientAppTypes: ["all"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA06":
      return {
        displayName: "CA06: Require multifactor authentication for risky sign-ins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          signInRiskLevels: ["medium", "high"],
        },
        grantControls: { operator: "OR", builtInControls: ["mfa"] },
      };
    case "CA07":
      return {
        displayName: "CA07: Require risk remediation for high-risk users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          userRiskLevels: ["high"],
        },
        grantControls: { operator: "AND", builtInControls: ["mfa", "passwordChange"] },
      };
    case "CA08":
      return {
        displayName: "CA08: Block Access from Untrusted Countries",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          locations: { includeLocations: ["All"], excludeLocations: ["AllTrusted"] },
        },
        grantControls: { operator: "OR", builtInControls: ["block"] },
      };
    case "CA09":
      return {
        displayName: "CA09: Require MDM-enrolled and compliant device to access cloud apps for all users",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: { includeUsers: ["All"], excludeUsers: [] },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
          platforms: { includePlatforms: ["windows", "macOS", "iOS", "android"] },
        },
        grantControls: { operator: "OR", builtInControls: ["compliantDevice", "domainJoinedDevice"] },
      };
    case "CA10":
      return {
        displayName: "CA10: Require phishing-resistant multifactor authentication for admins",
        state: "enabledForReportingButNotEnforced",
        conditions: {
          users: {
            includeRoles: [
              "62e90394-69f5-4237-9190-012177145e10", // Global Administrator
              "e8611ab8-c189-46e8-94e1-60213ab1f814", // Privileged Role Administrator
              "194ae4cb-b126-40b2-bd5b-6091b380977d", // Security Administrator
              "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", // Application Administrator
              "966707d0-3269-4727-9be2-8c3a10f19b9d", // User Administrator
              "c4e39bd9-1100-46d3-8c65-fb160da0071f", // Authentication Administrator
            ],
            excludeUsers: [],
          },
          applications: { includeApplications: ["All"] },
          clientAppTypes: ["all"],
        },
        grantControls: {
          operator: "OR",
          authenticationStrength: { id: "00000000-0000-0000-0000-000000000004" },
        },
      };
    default:
      throw new Error(`Unsupported baseline standard code: ${code}`);
  }
}

export async function deployConditionalAccessPolicy(
  tenant: Tenant,
  baselineCode: string
): Promise<{ success: boolean; policy?: any; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === baselineCode);
    const mockPolicy = {
      id: `ca-pol-${tenant.id}-${baselineCode.toLowerCase()}`,
      displayName: `${baselineCode}: ${baselineDef?.name || "Baseline Policy"}`,
      state: "enabledForReportingButNotEnforced",
      createdDateTime: new Date().toISOString(),
      modifiedDateTime: new Date().toISOString(),
    };
    return { success: true, policy: mockPolicy };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { success: false, error: `Authentication Error: ${error}` };
  }

  const payload = buildGraphCaPolicyPayload(baselineCode, tenant.defaultDomainName);

  try {
    const res = await graphFetch(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      },
      // A network exception here is ambiguous - the POST may have already reached
      // Graph and created the policy before the response was lost. Only retry a
      // structured 429/503 HTTP response, where Graph is explicitly confirming it
      // did not process the request.
      { retryOnNetworkError: false }
    );

    const data = await res.json();
    if (!res.ok) {
      return {
        success: false,
        error: data?.error?.message || `Failed to create policy in Microsoft Graph (HTTP ${res.status}: ${res.statusText})`,
      };
    }

    return { success: true, policy: data };
  } catch (err: any) {
    return { success: false, error: err.message || "Network error while connecting to Microsoft Graph." };
  }
}

// Shared by both ASR detection functions below. Graph's runHuntingQuery
// (v1.0, not beta) returns { schema, results }, with result row keys
// camelCased regardless of how the KQL `project`/`summarize` columns were
// capitalized - e.g. a `project ActionType` column comes back as
// `row.actionType`, not `row.ActionType`.
async function runHuntingQuery(token: string, query: string): Promise<{ rows?: any[]; error?: string }> {
  try {
    const res = await graphFetch(
      "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
      {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ Query: query, Timespan: "P30D" }),
      },
      { retryOnNetworkError: false }
    );
    const data = await res.json();
    if (!res.ok) {
      return { error: data?.error?.message || `Advanced Hunting query failed (HTTP ${res.status}: ${res.statusText})` };
    }
    return { rows: data.results || [] };
  } catch (err: any) {
    return { error: err.message || "Network error while running the Advanced Hunting query." };
  }
}

/**
 * Aggregate ASR detection activity for every rule at once (last 30 days),
 * for the module's per-row "N events" badges. On-demand only - never part of
 * fetchLiveTenantSnapshot - since it needs a separate ThreatHunting.Read.All
 * permission and a Defender for Endpoint P2 license many tenants may not
 * have, and would slow down every sync for one module's data otherwise.
 */
export async function fetchAsrDetectionSummaries(
  tenant: Tenant,
  currentRuleStates: { ruleId: string; mode: AsrRuleMode }[]
): Promise<{ summaries?: AsrRuleActivitySummary[]; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { summaries: synthesizeMockActivity(currentRuleStates, tenant.id) };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const { rows, error: queryError } = await runHuntingQuery(
    token,
    `DeviceEvents | where Timestamp > ago(30d) | where ActionType startswith "Asr" | summarize Count=count() by ActionType`
  );
  if (queryError) return { error: queryError };

  const actionTypeCounts: Record<string, number> = {};
  for (const row of rows || []) {
    if (row.actionType) actionTypeCounts[row.actionType] = row.count || 0;
  }
  return { summaries: buildActivitySummaries(actionTypeCounts) };
}

/**
 * Recent raw detection events for one specific rule (last 30 days, capped at
 * 50), fetched only when that rule's drawer is actually opened.
 */
export async function fetchAsrDetectionEvents(
  tenant: Tenant,
  ruleId: string
): Promise<{ events?: AsrDetectionEvent[]; error?: string }> {
  const def = ASR_RULE_DEFINITIONS.find((d) => d.id === ruleId);
  if (!def || !def.hasAdvancedHuntingTelemetry) {
    return { events: [] };
  }

  if (tenant.credentials.authMode === "mock") {
    const now = Date.now();
    const sampleFiles = ["invoice_2026.xlsm", "update_installer.exe", "quarterly_report.docm", "setup.ps1"];
    const count = Math.abs(
      def.advancedHuntingActionTypes.reduce((acc, t) => acc + t.length, 0) + tenant.id.length
    ) % 6;
    const events: AsrDetectionEvent[] = Array.from({ length: count }, (_, i) => ({
      timestamp: new Date(now - i * 6 * 60 * 60 * 1000).toISOString(),
      deviceName: `DEMO-WKS-${(i % 4) + 1}`,
      actionType: def.advancedHuntingActionTypes[i % def.advancedHuntingActionTypes.length],
      fileName: sampleFiles[i % sampleFiles.length],
      initiatingProcessFileName: i % 2 === 0 ? "winword.exe" : "powershell.exe",
    }));
    return { events };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const actionTypesList = def.advancedHuntingActionTypes.map((t) => `"${t}"`).join(", ");
  const { rows, error: queryError } = await runHuntingQuery(
    token,
    `DeviceEvents | where Timestamp > ago(30d) | where ActionType in (${actionTypesList}) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields | order by Timestamp desc | take 50`
  );
  if (queryError) return { error: queryError };

  const events: AsrDetectionEvent[] = (rows || []).map((row: any) => ({
    timestamp: row.timestamp,
    deviceName: row.deviceName,
    actionType: row.actionType,
    fileName: row.fileName || undefined,
    folderPath: row.folderPath || undefined,
    initiatingProcessFileName: row.initiatingProcessFileName || undefined,
    initiatingProcessCommandLine: row.initiatingProcessCommandLine || undefined,
    additionalFields: (() => {
      try {
        return row.additionalFields ? JSON.parse(row.additionalFields) : undefined;
      } catch {
        return undefined;
      }
    })(),
  }));
  return { events };
}

const ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID = "device_vendor_msft_policy_config_defender_attacksurfacereductionrules";

// Fetches (once per process, cached on globalThis - see asrSlugMapCacheGlobal
// above) Microsoft's own tenant-agnostic Settings Catalog metadata for the
// ASR root setting, then builds the slug->rule-GUID map via the pure,
// tested buildAsrSlugMap. A metadata fetch failure or an unmatched entry is
// pushed to syncErrors rather than thrown, so one missing/renamed slug never
// blocks every other rule from resolving correctly.
async function getAsrSettingsCatalogSlugMap(
  headers: HeadersInit,
  syncErrors: string[]
): Promise<Map<string, string>> {
  if (asrSlugMapCacheGlobal.clarity365AsrSlugMapCache) {
    return asrSlugMapCacheGlobal.clarity365AsrSlugMapCache;
  }

  try {
    const metadataResult = await fetchAllPages<any>(
      `https://graph.microsoft.com/beta/deviceManagement/configurationSettings?$filter=rootDefinitionId eq '${ASR_SETTINGS_CATALOG_ROOT_DEFINITION_ID}'`,
      headers
    );
    if (metadataResult.error) {
      syncErrors.push(`ASR Rules (Settings Catalog): could not load rule catalog metadata - ${metadataResult.error}`);
    }

    const { slugToRuleId, unmatchedCount } = buildAsrSlugMap(
      metadataResult.items.map((s: any) => ({
        settingDefinitionId: s.settingDefinitionId || s.id,
        displayName: s.displayName || "",
      }))
    );
    if (unmatchedCount > 0) {
      syncErrors.push(
        `ASR Rules (Settings Catalog): ${unmatchedCount} rule(s) in Microsoft's catalog could not be matched to a known ASR rule - they will be skipped rather than misattributed.`
      );
    }

    asrSlugMapCacheGlobal.clarity365AsrSlugMapCache = slugToRuleId;
    return slugToRuleId;
  } catch (err: any) {
    syncErrors.push(`ASR Rules (Settings Catalog): could not load rule catalog metadata - ${err.message || "network error"}`);
    return new Map();
  }
}

// Walks a Settings Catalog policy's /settings response to collect every
// selected leaf choice id (e.g.
// "..._blockexecutionofpotentiallyobfuscatedscripts_block"). The exact
// nested settingInstance shape below (choiceSettingValue / groupSettingCollectionValue
// / choiceSettingCollectionValue, each carrying further "children") follows
// Microsoft's generally-documented Settings Catalog pattern but was not
// verified against a live tenant response in this environment - if a real
// tenant's shape differs, this is the one place that needs correcting; the
// pure mapAsrSettingDefinitionIdsToSignals function downstream is unaffected
// either way since it only ever sees the flat string array this returns.
function flattenSettingsCatalogSelectedIds(settings: any[]): string[] {
  const ids: string[] = [];

  const visitInstance = (instance: any) => {
    if (!instance || typeof instance !== "object") return;

    const choiceValue = instance.choiceSettingValue;
    if (choiceValue) {
      if (typeof choiceValue.value === "string") ids.push(choiceValue.value);
      (choiceValue.children || []).forEach(visitInstance);
    }

    const choiceCollection = instance.choiceSettingCollectionValue;
    if (Array.isArray(choiceCollection)) {
      choiceCollection.forEach((entry: any) => {
        if (typeof entry?.value === "string") ids.push(entry.value);
        (entry?.children || []).forEach(visitInstance);
      });
    }

    const groupCollection = instance.groupSettingCollectionValue;
    if (Array.isArray(groupCollection)) {
      groupCollection.forEach((group: any) => (group?.children || []).forEach(visitInstance));
    }

    if (Array.isArray(instance.children)) {
      instance.children.forEach(visitInstance);
    }
  };

  settings.forEach((setting: any) => visitInstance(setting.settingInstance || setting));

  return ids;
}

// Flattens a legacy "Endpoint Security Template" intent's definitionValues
// (each an { id, definitionId, valueJson } row - definitionId is prefixed
// with "deviceConfiguration--windows10EndpointProtectionConfiguration_")
// into the same { propertyName, rawValue } shape the classic Device
// Configuration profile surface already produces directly, so both funnel
// through the one shared mapNamedPropertyValuesToSignals function.
const INTENT_DEFINITION_ID_PREFIX = "deviceConfiguration--windows10EndpointProtectionConfiguration_";

function extractIntentAsrProperties(definitionValues: any[]): { propertyName: string; rawValue: string }[] {
  const properties: { propertyName: string; rawValue: string }[] = [];

  for (const entry of definitionValues) {
    const definitionId: string = entry.definitionId || "";
    if (!definitionId.startsWith(INTENT_DEFINITION_ID_PREFIX)) continue;
    const propertyName = definitionId.slice(INTENT_DEFINITION_ID_PREFIX.length);

    let rawValue: unknown = entry.value;
    if (rawValue == null && typeof entry.valueJson === "string") {
      try {
        rawValue = JSON.parse(entry.valueJson);
      } catch {
        continue;
      }
    }
    if (typeof rawValue === "string") properties.push({ propertyName, rawValue });
  }

  return properties;
}

export async function fetchLiveTenantSnapshot(
  tenant: Tenant,
  existingSnapshot?: TenantSecuritySnapshot,
  onExoRefreshRotated?: (newRefreshToken: string) => void
): Promise<{ snapshot?: TenantSecuritySnapshot; error?: string }> {
  if (tenant.credentials.authMode === "mock") {
    return { snapshot: existingSnapshot };
  }

  const { token, error } = await getGraphAccessToken(tenant.credentials);
  if (error || !token) {
    return { error: `Authentication Error: ${error}` };
  }

  const headers = { Authorization: `Bearer ${token}` };
  const syncErrors: string[] = [];

  // 1. Fetch Conditional Access Policies
  let livePolicies: CAPolicyRule[] = [];
  try {
    const caResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      headers
    );
    if (caResult.error) syncErrors.push(`Conditional Access policies: ${caResult.error}`);

    livePolicies = caResult.items.map((p: any) => {
      const detectedCode = classifyPolicyBaselineCode(p);
      const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === detectedCode);

      // Graph's grantControls.authenticationStrength is a sibling object to
      // builtInControls, not an entry inside it - encode its presence as a marker
      // string in the array (matching this app's own convention, e.g. the
      // "authenticationStrength:PhishingResistantMFA" strings used when Clarity365
      // deploys its own CA10 policy) so ca-baseline-matcher.ts's array-based
      // hasAuthStrengthOrSession/controlsInclude checks can see it.
      const builtInControls: string[] = p.grantControls?.builtInControls || [];
      const authStrengthName = p.grantControls?.authenticationStrength?.displayName || p.grantControls?.authenticationStrength?.id;
      const grantControls = authStrengthName ? [...builtInControls, `authenticationStrength:${authStrengthName}`] : builtInControls;

      return {
        id: p.id,
        name: p.displayName,
        baselineCode: detectedCode,
        baselineTitle: baselineDef?.name,
        state: p.state as any,
        modifiedDateTime: p.modifiedDateTime || new Date().toISOString(),
        createdDateTime: p.createdDateTime || new Date().toISOString(),
        grantControls,
        conditions: {
          users: {
            include: p.conditions?.users?.includeUsers || p.conditions?.users?.includeRoles || [],
            exclude: p.conditions?.users?.excludeUsers || [],
            excludeGroupIds: p.conditions?.users?.excludeGroups || [],
            includeRoles: p.conditions?.users?.includeRoles || [],
          },
          applications: {
            include: p.conditions?.applications?.includeApplications || [],
            exclude: p.conditions?.applications?.excludeApplications || [],
          },
          clientAppTypes: p.conditions?.clientAppTypes || [],
          // Previously dropped entirely - CA06 (signInRiskLevels), CA07
          // (userRiskLevels), and CA08 (locations) all validate structurally
          // against these fields, so a live-synced policy that legitimately
          // satisfies them was still failing re-validation against the stored
          // snapshot even though the initial sync-time classification (run
          // against the raw Graph response above) correctly detected the code.
          platforms: {
            include: p.conditions?.platforms?.includePlatforms || [],
            exclude: p.conditions?.platforms?.excludePlatforms || [],
          },
          locations: {
            include: p.conditions?.locations?.includeLocations || [],
            exclude: p.conditions?.locations?.excludeLocations || [],
          },
          userRiskLevels: p.conditions?.userRiskLevels || [],
          signInRiskLevels: p.conditions?.signInRiskLevels || [],
        },
        matchesBaseline: !!detectedCode,
      };
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching CA policies:", err);
    syncErrors.push(`Conditional Access policies: ${err.message || "Unexpected error while processing policies."}`);
  }

  // 2. Fetch Users & Directory Roles
  let usersList: TenantAccountSummary["users"] = [];
  const adminUserRolesMap = new Map<string, string[]>(); // userId -> roleNames[]

  try {
    const usersResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,assignedLicenses,userType,signInActivity",
      headers
    );
    if (usersResult.error) syncErrors.push(`Users: ${usersResult.error}`);

    usersList = usersResult.items.map((u: any) => {
      const isGuest = u.userType?.toLowerCase() === "guest";
      const hasLicense = u.assignedLicenses && u.assignedLicenses.length > 0;
      const isEnabled = u.accountEnabled !== false;
      let classification: "licensed" | "unlicensed_active" | "disabled" | "guest" = "licensed";

      if (!isEnabled) {
        classification = "disabled";
      } else if (isGuest) {
        classification = "guest";
      } else if (hasLicense) {
        classification = "licensed";
      } else {
        classification = "unlicensed_active";
      }

      return {
        id: u.id,
        userPrincipalName: u.userPrincipalName,
        displayName: u.displayName || u.userPrincipalName,
        classification,
        licenses: u.assignedLicenses ? u.assignedLicenses.map((l: any) => l.skuId) : [],
        accountEnabled: isEnabled,
        department: u.department || "General",
        createdDateTime: u.createdDateTime || new Date().toISOString(),
        // signInActivity.lastSignInDateTime is Graph's authoritative "last
        // interactive sign-in" - undefined for a user who has never signed in
        // (requires AuditLog.Read.All, already held for auditLogs/signIns below).
        lastSignInDateTime: u.signInActivity?.lastSignInDateTime || undefined,
        riskFlag: classification === "unlicensed_active" ? "Active account without license assigned." : undefined,
      };
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching users:", err);
    syncErrors.push(`Users: ${err.message || "Unexpected error while processing users."}`);
  }

  try {
    // Query Directory Roles to identify privileged admins. $top on the expanded
    // members collection raises Graph's default expand page size; Graph does not
    // support @odata.nextLink cursoring *within* an expanded property, so an
    // exceptionally large single role's membership could still be capped here.
    const rolesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/directoryRoles?$expand=members($top=999)",
      headers
    );
    if (rolesResult.error) syncErrors.push(`Directory roles: ${rolesResult.error}`);

    rolesResult.items.forEach((role: any) => {
      const roleName = role.displayName || "Directory Role";
      if (role.members && Array.isArray(role.members)) {
        role.members.forEach((m: any) => {
          if (m.id) {
            const existing = adminUserRolesMap.get(m.id) || [];
            existing.push(roleName);
            adminUserRolesMap.set(m.id, existing);
          }
        });
      }
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching directory roles:", err);
    syncErrors.push(`Directory roles: ${err.message || "Unexpected error while processing roles."}`);
  }

  // 3. Fetch Sign-In Logs
  let signInsList: SignInEvent[] = [];
  try {
    // Some tenant configurations reject a $top=250 audit log request with 400;
    // fall back to a smaller page size for the first page, then paginate normally.
    // Sign-in volume can be very high, so this is capped tighter than other lists.
    const signInsResult = await fetchAllPages<any>(
      [
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=250",
        "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100",
      ],
      headers,
      20
    );
    if (signInsResult.error) syncErrors.push(`Sign-in logs: ${signInsResult.error}`);

    signInsList = signInsResult.items.map((s: any) => {
      const appliedPolicies = (s.appliedConditionalAccessPolicies || []).map((p: any) => ({
        id: p.id || "",
        displayName: p.displayName || "Conditional Access Policy",
        result: p.result || "notApplied",
        enforcedGrantControls: p.enforcedGrantControls || [],
        enforcedSessionControls: p.enforcedSessionControls || [],
      }));

      const hasReportOnlyFailure = appliedPolicies.some(
        (p: any) => p.result === "reportOnlyFailure"
      );
      const reportOnlyFailedPolicies = appliedPolicies
        .filter((p: any) => p.result === "reportOnlyFailure")
        .map((p: any) => p.displayName);

      const isBlocked =
        appliedPolicies.some((p: any) => p.result === "failure") ||
        s.status?.errorCode === 53003;
      const isFailed = s.status?.errorCode !== 0;

      let status: SignInStatus = "success";
      if (isBlocked) {
        status = "ca_blocked";
      } else if (hasReportOnlyFailure) {
        status = "report_only_failed";
      } else if (isFailed) {
        status = "failed";
      }

      const errorCode = s.status?.errorCode || 0;
      let failureReason = s.status?.failureReason;
      if (!failureReason || failureReason === "Other." || failureReason === "None") {
        if (s.status?.additionalDetails) {
          failureReason = s.status.additionalDetails;
        } else if (errorCode !== 0) {
          failureReason = `Error ${errorCode}: Authentication or conditional access requirement not met`;
        } else {
          failureReason = "Authentication successful (All controls satisfied)";
        }
      }

      return {
        id: s.id,
        createdDateTime: s.createdDateTime || new Date().toISOString(),
        userPrincipalName: s.userPrincipalName || "unknown@domain.com",
        userDisplayName: s.userDisplayName || s.userPrincipalName || "Unknown User",
        userId: s.userId || "",
        ipAddress: s.ipAddress || "0.0.0.0",
        location: {
          city: s.location?.city || "Unknown",
          state: s.location?.state || "",
          country: s.location?.countryOrRegion || "Unknown",
        },
        clientApp: s.clientAppUsed || "Browser",
        appDisplayName: s.appDisplayName || "Microsoft 365 Cloud App",
        status,
        errorCode,
        failureReason,
        isRisky:
          s.riskLevelDuringSignIn === "medium" ||
          s.riskLevelDuringSignIn === "high" ||
          s.riskState === "atRisk",
        riskLevel: (s.riskLevelDuringSignIn || s.riskLevelAggregated || "none").toLowerCase() as any,
        deviceDetail: {
          deviceId: s.deviceDetail?.deviceId || "",
          displayName: s.deviceDetail?.displayName || "",
          operatingSystem: s.deviceDetail?.operatingSystem || "Unknown OS",
          browser: s.deviceDetail?.browser || "Unknown Browser",
          isCompliant: !!s.deviceDetail?.isCompliant,
          isManaged: !!s.deviceDetail?.isManaged,
          trustType: s.deviceDetail?.trustType || undefined,
        },
        appliedConditionalAccessPolicies: appliedPolicies,
        hasReportOnlyFailure,
        reportOnlyFailedPolicies,
      };
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching sign-in logs:", err);
    syncErrors.push(`Sign-in logs: ${err.message || "Unexpected error while processing sign-in logs."}`);
  }

  // 4. Fetch MFA & Authentication Methods
  let mfaProfilesList: UserMfaProfile[] = [];
  try {
    const mfaResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999",
      headers
    );
    if (mfaResult.error) syncErrors.push(`MFA registration details: ${mfaResult.error}`);

    const hasCaMfaEnforced = livePolicies.some(
      (p) => (p.baselineCode === "CA02" || p.baselineCode === "CA03") && p.state === "enabled"
    );

    if (mfaResult.items.length > 0) {
      const registrationMap = new Map<string, any>();
      mfaResult.items.forEach((reg: any) => {
        registrationMap.set(reg.id || reg.userPrincipalName?.toLowerCase(), reg);
      });

      mfaProfilesList = usersList.map((u) => {
        const reg = registrationMap.get(u.id) || registrationMap.get(u.userPrincipalName.toLowerCase());
        const roles = adminUserRolesMap.get(u.id) || [];
        const isAdmin = roles.length > 0 || (reg && !!reg.isAdmin);

        const { registeredMethods, defaultMethod, mfaRegistered, isWeakAuth, authStrength } = classifyUserAuthMethods(
          reg?.methodsRegistered,
          reg ? !!reg.isMfaRegistered : false
        );

        return {
          id: u.id,
          userPrincipalName: u.userPrincipalName,
          displayName: u.displayName,
          jobTitle: "Enterprise User",
          department: u.department || "General",
          accountEnabled: u.accountEnabled,
          isAdmin,
          adminRoles: roles.length > 0 ? roles : isAdmin ? ["Global Administrator"] : undefined,
          mfaRegistered,
          mfaEnforcedByPolicy: hasCaMfaEnforced || isAdmin,
          defaultMethod,
          registeredMethods: registeredMethods.length > 0 ? registeredMethods : ["none"],
          isWeakAuth,
          passwordLastSetDateTime: u.createdDateTime,
          // Prefer the authoritative signInActivity value captured on the user
          // object above; fall back to the most recent audit log sign-in event,
          // and finally "" (never signed in) - NOT today's date, which would
          // misrepresent every unused account as active.
          lastSignInDateTime:
            u.lastSignInDateTime ||
            signInsList.find((s) => s.userPrincipalName.toLowerCase() === u.userPrincipalName.toLowerCase())
              ?.createdDateTime ||
            "",
          isSsprRegistered: reg ? !!reg.isSsprRegistered : false,
          isPasswordlessCapable: reg ? !!reg.isPasswordlessCapable : defaultMethod === "passkey_fido2",
          methodsCount: registeredMethods.length,
          authStrength,
        };
      });
    }

    // Fallback: If registration report was forbidden or returned 0 rows, synthesize profiles from directory users & sign-in logs
    if (mfaProfilesList.length === 0 && usersList.length > 0) {
      mfaProfilesList = usersList.map((u) => {
        const roles = adminUserRolesMap.get(u.id) || [];
        const isAdmin = roles.length > 0;

        // Check if user has successful sign-ins with MFA controls satisfied
        const userSignIns = signInsList.filter((s) => s.userPrincipalName.toLowerCase() === u.userPrincipalName.toLowerCase());
        const hasPassedMfaInSignIns = userSignIns.some((s) => s.status === "success");

        const defaultMethod = hasPassedMfaInSignIns ? "ms_authenticator_push" : "none";
        const mfaRegistered = hasPassedMfaInSignIns;
        const isWeakAuth = !mfaRegistered;

        return {
          id: u.id,
          userPrincipalName: u.userPrincipalName,
          displayName: u.displayName,
          jobTitle: isAdmin ? "Directory Administrator" : "Enterprise User",
          department: u.department || "General",
          accountEnabled: u.accountEnabled,
          isAdmin,
          adminRoles: roles.length > 0 ? roles : undefined,
          mfaRegistered,
          mfaEnforcedByPolicy: hasCaMfaEnforced || isAdmin,
          defaultMethod,
          registeredMethods: mfaRegistered ? ["ms_authenticator_push"] : ["none"],
          isWeakAuth,
          passwordLastSetDateTime: u.createdDateTime,
          lastSignInDateTime: u.lastSignInDateTime || userSignIns[0]?.createdDateTime || "",
          isSsprRegistered: mfaRegistered,
          isPasswordlessCapable: false,
          methodsCount: mfaRegistered ? 1 : 0,
          authStrength: mfaRegistered ? "strong" : "none",
        };
      });
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MFA registration details:", err);
    syncErrors.push(`MFA registration details: ${err.message || "Unexpected error while processing MFA data."}`);
  }

  // 5. Fetch Intune Managed Devices
  let intuneDevices: IntuneDevice[] = [];
  try {
    const devicesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999&$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,model,manufacturer,serialNumber,imei,enrolledDateTime,managementAgent,managedDeviceOwnerType,deviceEnrollmentType,totalStorageSpaceInBytes,freeStorageSpaceInBytes,deviceCategoryDisplayName,azureADDeviceId,jailBroken,complianceGracePeriodExpirationDateTime,wiFiMacAddress",
      headers
    );
    if (devicesResult.error) syncErrors.push(`Intune devices: ${devicesResult.error}`);
    intuneDevices = devicesResult.items.map(mapManagedDeviceToIntuneDevice);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune devices:", err);
    syncErrors.push(`Intune devices: ${err.message || "Unexpected error while processing devices."}`);
  }

  // 6. Fetch Intune Endpoint Security policy counts (tenant-wide aggregates,
  // not per-device). Endpoint Security "Intents" is a Graph beta surface -
  // category matching here is best-effort and worth confirming against a
  // real tenant; a failure here doesn't block the device inventory above.
  let antivirusPoliciesCount = 0;
  let edrPoliciesCount = 0;
  // Hoisted so the ASR configuration section below can reuse this same list
  // (it's the "Endpoint Security Templates" intents surface) instead of
  // issuing a second, identical $expand=categories request.
  let intentsItems: any[] = [];
  try {
    const intentsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/intents?$expand=categories",
      headers
    );
    if (intentsResult.error) syncErrors.push(`Intune Endpoint Security policies: ${intentsResult.error}`);
    intentsItems = intentsResult.items;
    intentsItems.forEach((intent: any) => {
      const categoryNames: string[] = (intent.categories || []).map((c: any) => (c.displayName || "").toLowerCase());
      if (categoryNames.some((c) => c.includes("antivirus"))) antivirusPoliciesCount++;
      if (categoryNames.some((c) => c.includes("detection and response") || c.includes("edr"))) edrPoliciesCount++;
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune Endpoint Security policies:", err);
    syncErrors.push(`Intune Endpoint Security policies: ${err.message || "Unexpected error while processing policies."}`);
  }

  // 6b. Fetch real Attack Surface Reduction rule configuration state. Real
  // tenants can configure ASR rules via up to three independent, mergeable
  // Intune surfaces (verified against Microsoft Learn, not guessed) - a
  // partial implementation covering only one would silently under-report
  // for tenants using another, which is exactly the class of bug this
  // section exists to close (see ai-context-vault/Optimization/Optimization
  // Plan.md item 7). All signal collection/merge logic lives in the pure,
  // tested asr-configuration-mapper.ts; this section only walks raw Graph
  // JSON into the flat shapes those functions expect.
  const asrSignals: AsrConfigSignal[] = [];
  let asrConfigFetchSucceeded = false;

  // Surface 1: modern Settings Catalog ("Endpoint security > Attack surface
  // reduction policy"). Microsoft's own docs say most tenants use this
  // format today, making it the highest-value of the three.
  try {
    const catalogPoliciesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityAttackSurfaceReduction'",
      headers
    );
    if (catalogPoliciesResult.error) {
      syncErrors.push(`ASR Rules (Settings Catalog): ${catalogPoliciesResult.error}`);
    } else {
      asrConfigFetchSucceeded = true;
    }

    if (catalogPoliciesResult.items.length > 0) {
      const slugToRuleId = await getAsrSettingsCatalogSlugMap(headers, syncErrors);

      for (const policy of catalogPoliciesResult.items) {
        const settingsResult = await fetchAllPages<any>(
          `https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('${policy.id}')/settings`,
          headers
        );
        if (settingsResult.error) {
          syncErrors.push(`ASR Rules (Settings Catalog): ${settingsResult.error}`);
          continue;
        }
        const selectedIds = flattenSettingsCatalogSelectedIds(settingsResult.items);
        const policyName = policy.name || policy.displayName || "Attack Surface Reduction Policy";
        asrSignals.push(...mapAsrSettingDefinitionIdsToSignals(selectedIds, policyName, slugToRuleId));
      }
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR Settings Catalog policies:", err);
    syncErrors.push(`ASR Rules (Settings Catalog): ${err.message || "Unexpected error while processing policies."}`);
  }

  // Surface 2: legacy classic Device Configuration profile ("Endpoint
  // protection" profile, windows10EndpointProtectionConfiguration). Simplest
  // to read - each rule is a flat, named top-level property - but only 15 of
  // the 19 catalog rules are expressible in this older schema.
  try {
    const deviceConfigResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations",
      headers
    );
    if (deviceConfigResult.error) {
      syncErrors.push(`ASR Rules (Device Configuration): ${deviceConfigResult.error}`);
    } else {
      asrConfigFetchSucceeded = true;
    }

    deviceConfigResult.items
      .filter((c: any) => c["@odata.type"] === "#microsoft.graph.windows10EndpointProtectionConfiguration")
      .forEach((profile: any) => {
        const properties = Object.keys(LEGACY_ASR_PROPERTY_TO_RULE_ID)
          .filter((propertyName) => profile[propertyName] != null)
          .map((propertyName) => ({ propertyName, rawValue: profile[propertyName] }));
        const profileName = profile.displayName || "Endpoint Protection Profile";
        asrSignals.push(...mapNamedPropertyValuesToSignals(properties, profileName));
      });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR device configuration profiles:", err);
    syncErrors.push(`ASR Rules (Device Configuration): ${err.message || "Unexpected error while processing profiles."}`);
  }

  // Surface 3: older "Endpoint Security Templates" intent-based policies -
  // being phased out in favor of the Settings Catalog but not yet retired.
  // Reuses intentsItems already fetched above instead of a second request,
  // and the exact same category-name-matching convention already
  // established there for antivirus/EDR.
  try {
    const asrIntents = intentsItems.filter((intent: any) => {
      const categoryNames: string[] = (intent.categories || []).map((c: any) => (c.displayName || "").toLowerCase());
      return categoryNames.some((c) => c.includes("attack surface reduction"));
    });

    for (const intent of asrIntents) {
      const definitionValuesResult = await fetchAllPages<any>(
        `https://graph.microsoft.com/beta/deviceManagement/intents('${intent.id}')/definitionValues?$expand=settingInstances`,
        headers
      );
      if (definitionValuesResult.error) {
        syncErrors.push(`ASR Rules (Endpoint Security Templates): ${definitionValuesResult.error}`);
        continue;
      }
      asrConfigFetchSucceeded = true;
      const properties = extractIntentAsrProperties(definitionValuesResult.items);
      const intentName = intent.displayName || "Endpoint Security Template";
      asrSignals.push(...mapNamedPropertyValuesToSignals(properties, intentName));
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching ASR Endpoint Security Template policies:", err);
    syncErrors.push(`ASR Rules (Endpoint Security Templates): ${err.message || "Unexpected error while processing policies."}`);
  }

  // If literally every surface failed, leave asrRules untouched below
  // (preserves last-good data on a transient/permission failure) rather than
  // overwriting it with a confident-looking but empty result.
  const asrRulesLive: AsrRuleState[] | null = asrConfigFetchSucceeded ? mergeAsrRuleStates(asrSignals) : null;

  // 7. Fetch Microsoft Secure Score & control profiles
  let secureScoreData: TenantSecureScore | null = null;
  try {
    const scoresResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/security/secureScores?$top=100",
      headers
    );
    if (scoresResult.error) syncErrors.push(`Secure Score: ${scoresResult.error}`);

    if (scoresResult.items.length > 0) {
      const profilesResult = await fetchAllPages<any>(
        "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles?$top=999",
        headers
      );
      if (profilesResult.error) syncErrors.push(`Secure Score control profiles: ${profilesResult.error}`);

      const profileMap = new Map<string, any>();
      profilesResult.items.forEach((p: any) => profileMap.set(p.id, p));

      const historyEntries = scoresResult.items.map((s: any) => ({
        createdDateTime: s.createdDateTime,
        currentScore: s.currentScore || 0,
        maxScore: s.maxScore || 0,
      }));

      const latest = [...scoresResult.items].sort(
        (a: any, b: any) => new Date(b.createdDateTime).getTime() - new Date(a.createdDateTime).getTime()
      )[0];

      const controls = (latest.controlScores || []).map((cs: any) =>
        mapSecureScoreControl(cs, profileMap.get(cs.controlName))
      );

      secureScoreData = {
        currentScore: latest.currentScore || 0,
        maxScore: latest.maxScore || 0,
        percentage: latest.maxScore > 0 ? Math.round((latest.currentScore / latest.maxScore) * 1000) / 10 : 0,
        delta30Days: computeScoreDelta(historyEntries, 30),
        delta90Days: computeScoreDelta(historyEntries, 90),
        industryBenchmark: extractIndustryBenchmark(latest.averageComparativeScores),
        history: buildSecureScoreHistory(historyEntries),
        controls,
      };
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Secure Score:", err);
    syncErrors.push(`Secure Score: ${err.message || "Unexpected error while processing secure score."}`);
  }

  // 8. Fetch MDO Policies & TABL via Exchange Online (see exo-client.ts -
  // Defender for Office 365 policies aren't reachable via standard Graph).
  // Skipped silently (not pushed as a sync error) if Exchange Online hasn't
  // been connected yet, since that's a separate, optional credential from
  // the Graph client secret used everywhere else - its absence isn't a
  // fault, just a not-yet-configured feature. If it IS connected, a fetch
  // failure IS surfaced as a real sync error.
  let mdoPolicies: MdoThreatPolicy[] | null = null;
  let mdoTabl: TablEntry[] | null = null;
  if (tenant.credentials.exoRefreshToken) {
    try {
      const { policies, tabl, policyErrors, tablErrors } = await fetchMdoPoliciesAndTabl(tenant, onExoRefreshRotated);
      policyErrors.forEach((e) => syncErrors.push(`MDO Policies: ${e}`));
      tablErrors.forEach((e) => syncErrors.push(`MDO TABL: ${e}`));
      mdoPolicies = policies;
      mdoTabl = tabl;
    } catch (err: any) {
      console.error("[Graph Client] Error fetching MDO policies via Exchange Online:", err);
      syncErrors.push(`MDO Policies: ${err.message || "Unexpected error while processing Exchange Online data."}`);
    }
  }

  // 8.5. Fetch MDO-sourced threat detections via Microsoft Graph's Security
  // Alerts API. Independent of the Exchange Online connection above (this is
  // a plain Graph client-secret call, same as Secure Score/Intune) - useful
  // even for a tenant that hasn't connected EXO at all. Scoped to the last 30
  // days to match the "Threats Detected (30d)" framing in the UI. Exact OData
  // filter syntax/field names below are based on the documented alerts_v2
  // schema - worth confirming against a live tenant, same caveat as
  // mdo-mapper.ts's other Exchange-shape assumptions.
  let mdoAlerts: MdoThreatAlert[] | null = null;
  try {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
    const filter = `serviceSource eq 'microsoftDefenderForOffice365' and createdDateTime ge ${thirtyDaysAgo}`;
    const alertsResult = await fetchAllPages<any>(
      `https://graph.microsoft.com/v1.0/security/alerts_v2?$filter=${encodeURIComponent(filter)}&$top=999`,
      headers
    );
    if (alertsResult.error) syncErrors.push(`MDO Threat Alerts: ${alertsResult.error}`);
    mdoAlerts = alertsResult.items.map(mapMdoAlert);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching MDO threat alerts:", err);
    syncErrors.push(`MDO Threat Alerts: ${err.message || "Unexpected error while processing threat alerts."}`);
  }

  // 8.6. Fetch live mailbox delegations, forwarding rules, and mailbox-audit
  // status via the same Exchange Online connection MDO uses (Module 6/7).
  // Gated the same way as MDO policies above - skipped silently if EXO isn't
  // connected, surfaced as a real sync error (prefixed "Mailflow:") if it is
  // connected but the fetch fails.
  let mailboxesLive: MailboxItem[] | null = null;
  let emailForwardingLive: EmailForwardingRule[] | null = null;
  let transportRulesLive: MailflowTransportRule[] | null = null;
  let connectorsLive: MailflowConnector[] | null = null;
  let remoteDomainAutoForwardBlocked: boolean | null | undefined = undefined;
  let externalSenderTagEnabled: boolean | null | undefined = undefined;
  let mailboxAuditingEnabled: boolean | null | undefined = undefined;
  if (tenant.credentials.exoRefreshToken) {
    try {
      const result = await fetchMailflowData(tenant, onExoRefreshRotated);
      result.errors.forEach((e) => syncErrors.push(`Mailflow: ${e}`));
      // Cross-reference the Graph license data already fetched for Module 5
      // (usersList, step 2) rather than making a second call for the same
      // information - Get-Mailbox itself has no license concept.
      const licensedUpns = new Set(
        usersList.filter((u) => u.classification === "licensed").map((u) => u.userPrincipalName.toLowerCase())
      );
      mailboxesLive = result.mailboxes.map((mbx) => ({
        ...mbx,
        hasDirectLicense: licensedUpns.has(mbx.userPrincipalName.toLowerCase()),
      }));
      emailForwardingLive = result.emailForwarding;
      transportRulesLive = result.transportRules;
      connectorsLive = result.connectors;
      remoteDomainAutoForwardBlocked = result.remoteDomainAutoForwardBlocked;
      externalSenderTagEnabled = result.externalSenderTagEnabled;
      mailboxAuditingEnabled = result.mailboxAuditingEnabled;
    } catch (err: any) {
      console.error("[Graph Client] Error fetching mailflow data via Exchange Online:", err);
      syncErrors.push(`Mailflow: ${err.message || "Unexpected error while processing mailbox/forwarding data."}`);
    }
  }

  // 8.7. Domain Authentication (SPF/DKIM/DMARC). DKIM comes from the EXO
  // connection above; SPF/DMARC are plain public DNS TXT lookups run for
  // every accepted domain, independent of any Microsoft 365 credential -
  // but the accepted-domain list itself still needs EXO's
  // Get-AcceptedDomain, so this whole step is gated the same way as the
  // rest of Exchange & Mailflow rather than running standalone.
  let domainAuthLive: DomainAuthStatus[] | null = null;
  if (tenant.credentials.exoRefreshToken) {
    try {
      const { domains, dkimByDomain, errors: domainErrors } = await fetchAcceptedDomainsAndDkim(tenant, onExoRefreshRotated);
      domainErrors.forEach((e) => syncErrors.push(`Domain Auth: ${e}`));
      domainAuthLive = await Promise.all(
        domains.map(async ({ domain, isDefaultDomain }) => {
          const [spf, dmarc] = await Promise.all([checkSpfRecord(domain), checkDmarcRecord(domain)]);
          return {
            domain,
            isDefaultDomain,
            dkim: dkimByDomain.get(domain) || {
              status: "fail" as const,
              detail: "DKIM has never been configured for this domain.",
              recommendation: "Run Enable-DkimSigningConfig, then publish the two CNAME selector records Exchange provides at your DNS host.",
            },
            spf,
            dmarc,
          };
        })
      );
    } catch (err: any) {
      console.error("[Graph Client] Error checking domain authentication:", err);
      syncErrors.push(`Domain Auth: ${err.message || "Unexpected error while checking SPF/DKIM/DMARC."}`);
    }
  }

  // 8.8. Groups & Distribution - pure Graph, independent of the EXO
  // connection above. Exchange has no bulk "every group's owners/members"
  // endpoint any more than it does for mailboxes, so the same N+1-with-a-cap
  // shape from the mailflow mailbox scan applies here: one extra owners +
  // members round trip per group, capped for sync performance.
  let groupsLive: TenantGroup[] | null = null;
  let groupExpirationPolicyEnabled: boolean | undefined;
  let groupSelfServiceCreationRestricted: boolean | undefined;
  let groupNamingPolicyEnabled: boolean | undefined;
  try {
    const groupsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/groups?$top=999&$select=id,displayName,mailNickname,groupTypes,mailEnabled,securityEnabled,isAssignableToRole,onPremisesSyncEnabled,createdDateTime,membershipRule",
      headers
    );
    if (groupsResult.error) syncErrors.push(`Groups: ${groupsResult.error}`);

    const cappedGroups = groupsResult.items.slice(0, MAX_GROUPS_FOR_MEMBER_SCAN);
    if (groupsResult.items.length > MAX_GROUPS_FOR_MEMBER_SCAN) {
      syncErrors.push(
        `Groups: Owner/member scan capped at the first ${MAX_GROUPS_FOR_MEMBER_SCAN} groups for sync performance - this tenant may have more.`
      );
    }

    groupsLive = await Promise.all(
      cappedGroups.map(async (raw: any) => {
        const [ownersResult, membersResult] = await Promise.all([
          fetchAllPages<any>(`https://graph.microsoft.com/v1.0/groups/${raw.id}/owners?$select=userPrincipalName&$top=100`, headers, 1),
          fetchAllPages<any>(
            `https://graph.microsoft.com/v1.0/groups/${raw.id}/members?$select=userPrincipalName,userType&$top=100`,
            headers,
            1
          ),
        ]);
        const ownerNames = ownersResult.items.map((o: any) => o.userPrincipalName).filter(Boolean);
        return mapGroup(raw, ownerNames, membersResult.items);
      })
    );

    // GET /groupSettings - tenant-wide expiration/self-service-creation/naming
    // policy. A 403 here (missing permission) is common and shouldn't block
    // the rest of the group data above from being used.
    const settingsResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/groupSettings", headers);
    if (settingsResult.error) {
      syncErrors.push(`Group Settings: ${settingsResult.error}`);
    } else {
      groupExpirationPolicyEnabled = mapGroupExpirationPolicyEnabled(settingsResult.items);
      groupSelfServiceCreationRestricted = mapGroupSelfServiceCreationRestricted(settingsResult.items);
      groupNamingPolicyEnabled = mapGroupNamingPolicyEnabled(settingsResult.items);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching groups:", err);
    syncErrors.push(`Groups: ${err.message || "Unexpected error while processing groups."}`);
  }

  // 8.9. SharePoint, OneDrive & Storage - depends on groupsLive (fetched
  // above) to resolve a team site's owner via its linked M365 group. No bulk
  // "every site's storage quota" Graph endpoint exists any more than for
  // groups' owners/members, so the same N+1-with-a-cap shape applies: one
  // extra drive-quota round trip per site, capped for sync performance.
  let sharePointLive: SharePointTenantPolicy | null = null;
  try {
    let tenantSharingLevel: SharePointTenantPolicy["tenantSharingLevel"] = "NewAndExistingGuests";
    let defaultLinkType: SharePointTenantPolicy["defaultLinkType"] = "Internal";
    let anonymousLinkExpirationDays = 0;

    const settingsRes = await graphFetch("https://graph.microsoft.com/v1.0/admin/sharepoint/settings", { headers });
    if (settingsRes.ok) {
      const settingsRaw = await settingsRes.json();
      ({ tenantSharingLevel, defaultLinkType, anonymousLinkExpirationDays } = mapTenantSharingSettings(settingsRaw));
    } else {
      syncErrors.push(`SharePoint Settings: HTTP ${settingsRes.status} while reading tenant sharing settings.`);
    }

    const sitesResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/sites?search=*&$select=id,displayName,name,webUrl,createdDateTime,lastModifiedDateTime,sharepointIds",
      headers
    );
    if (sitesResult.error) syncErrors.push(`SharePoint Sites: ${sitesResult.error}`);

    const cappedSites = sitesResult.items.slice(0, MAX_SITES_FOR_STORAGE_SCAN);
    if (sitesResult.items.length > MAX_SITES_FOR_STORAGE_SCAN) {
      syncErrors.push(
        `SharePoint Sites: Storage scan capped at the first ${MAX_SITES_FOR_STORAGE_SCAN} sites for sync performance - this tenant may have more.`
      );
    }

    const groupsById = new Map<string, TenantGroup>((groupsLive || []).map((g) => [g.id, g]));

    const sites = await Promise.all(
      cappedSites.map(async (raw: any) => {
        const driveRes = await graphFetch(`https://graph.microsoft.com/v1.0/sites/${raw.id}/drive?$select=quota`, { headers }, { maxRetries: 1 });
        const driveQuota = driveRes.ok ? (await driveRes.json())?.quota : undefined;
        return mapSharePointSite(raw, driveQuota, tenantSharingLevel, groupsById);
      })
    );

    const totalStorageUsedTB = sites.reduce((sum, s) => sum + s.storageUsedGB, 0) / 1024;
    const totalStorageAllocatedTB = sites.reduce((sum, s) => sum + s.storageAllocatedGB, 0) / 1024;

    sharePointLive = {
      tenantSharingLevel,
      defaultLinkType,
      anonymousLinkExpirationDays,
      totalStorageAllocatedTB,
      totalStorageUsedTB,
      sites,
    };
  } catch (err: any) {
    console.error("[Graph Client] Error fetching SharePoint data:", err);
    syncErrors.push(`SharePoint: ${err.message || "Unexpected error while processing SharePoint sites."}`);
  }

  // 8.95. Fetch App Registrations & Enterprise Applications (Module 9)
  let appRegistrationsLive: AppRegistrationItem[] | null = null;
  try {
    const appsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/applications?$top=999&$select=id,appId,displayName,publisherDomain,createdDateTime,keyCredentials,passwordCredentials,requiredResourceAccess,signInAudience",
      headers
    );
    if (appsResult.error) {
      syncErrors.push(`App Registrations: ${appsResult.error}`);
    } else {
      appRegistrationsLive = appsResult.items.map(mapAppRegistration);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching app registrations:", err);
    syncErrors.push(`App Registrations: ${err.message || "Unexpected error while processing applications."}`);
  }

  // 8.96. Fetch Subscribed SKUs & detect Tenant Capabilities / Licenses
  let capabilitiesLive: TenantCapability[] | null = null;
  let licenseSkusLive: TenantLicenseSku[] | null = null;
  const skuIdToPartNumber = new Map<string, string>();
  try {
    const skusResult = await fetchAllPages<any>("https://graph.microsoft.com/v1.0/subscribedSkus", headers);
    if (skusResult.error) {
      syncErrors.push(`Tenant Licenses (SubscribedSkus): ${skusResult.error}`);
    } else if (skusResult.items.length > 0) {
      capabilitiesLive = mapSubscribedSkusToCapabilities(skusResult.items);
      licenseSkusLive = skusResult.items.map((s: any) => {
        const consumedUnits = s.consumedUnits || 0;
        const enabledUnits = s.prepaidUnits?.enabled || 0;
        return {
          skuId: s.skuId,
          skuPartNumber: s.skuPartNumber,
          consumedUnits,
          enabledUnits,
          availableUnits: Math.max(0, enabledUnits - consumedUnits),
        };
      });
      skusResult.items.forEach((s: any) => {
        if (s.skuId && s.skuPartNumber) skuIdToPartNumber.set(s.skuId, s.skuPartNumber);
      });
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching subscribed SKUs:", err);
    syncErrors.push(`Tenant Licenses: ${err.message || "Unexpected error while processing subscribed SKUs."}`);
  }

  // Resolve per-user assignedLicenses skuId GUIDs (fetched in step 2 above, before this
  // tenant-wide SKU list was available) into human-readable skuPartNumber tokens, e.g.
  // "SPE_E5" - required for any per-user license-name matching (see admin-hygiene-matcher.ts).
  if (skuIdToPartNumber.size > 0 && usersList.length > 0) {
    usersList = usersList.map((u) => ({
      ...u,
      licenses: u.licenses.map((skuId) => skuIdToPartNumber.get(skuId) || skuId),
    }));
  }

  // 8.97. Fetch Microsoft Defender XDR Incidents (Module 8.6: SOC & Event Response)
  let incidentsLive: SecurityIncidentItem[] | null = null;
  try {
    const incidentsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/v1.0/security/incidents?$top=100&$expand=alerts",
      headers
    );
    if (incidentsResult.error) {
      syncErrors.push(`Security Incidents: ${incidentsResult.error}`);
    } else if (incidentsResult.items.length > 0) {
      incidentsLive = incidentsResult.items.map(mapSecurityIncident);
    }
  } catch (err: any) {
    console.error("[Graph Client] Error fetching security incidents:", err);
    syncErrors.push(`Security Incidents: ${err.message || "Unexpected error while processing incidents."}`);
  }

  // Fallback: If tenant doesn't have Defender XDR incidents, synthesize from MDO alerts
  if (!incidentsLive && mdoAlerts && mdoAlerts.length > 0) {
    incidentsLive = synthesizeIncidentsFromMdoAlerts(mdoAlerts);
  }

  // 9. Compute baseline coverage
  const deployedBaselineCodes = new Set(livePolicies.map((p) => p.baselineCode).filter(Boolean));
  const coveragePercent = computeBaselineCoveragePercent(deployedBaselineCodes.size, CA_BASELINE_STANDARDS.length);

  const syncHealth: SyncHealth = {
    isPartial: syncErrors.length > 0,
    errors: syncErrors,
    lastAttemptAt: new Date().toISOString(),
  };

  // 10. Build or update snapshot. The fields below are all overwritten immediately
  // after with the data just fetched - createBlankSnapshot only needs to supply a
  // structurally valid starting point for a tenant's first-ever sync.
  const base = existingSnapshot || createBlankSnapshot(tenant);

  base.tenant = {
    ...tenant,
    lastSyncTimestamp: new Date().toISOString(),
    connectionStatus: syncHealth.isPartial ? "degraded" : "healthy",
  };
  base.syncHealth = syncHealth;
  base.conditionalAccess = {
    baselineCoverageScore: coveragePercent,
    baselineDefinitions: CA_BASELINE_STANDARDS,
    policies: livePolicies.length > 0 ? livePolicies : base.conditionalAccess.policies,
  };

  if (mfaProfilesList.length > 0) {
    base.mfaAudit = mfaProfilesList;
  }

  if (signInsList.length > 0) {
    base.signIns = signInsList;
  }

  if (usersList.length > 0) {
    base.accountClassification = {
      totalAccounts: usersList.length,
      licensedUsersCount: usersList.filter((u) => u.classification === "licensed").length,
      unlicensedActiveCount: usersList.filter((u) => u.classification === "unlicensed_active").length,
      disabledAccountsCount: usersList.filter((u) => u.classification === "disabled").length,
      guestAccountsCount: usersList.filter((u) => u.classification === "guest").length,
      users: usersList,
    };
  }

  if (intuneDevices.length > 0) {
    const compliantCount = intuneDevices.filter((d) => d.complianceState === "compliant").length;
    base.intune = {
      totalDevices: intuneDevices.length,
      compliantDevices: compliantCount,
      nonCompliantDevices: intuneDevices.length - compliantCount,
      antivirusPoliciesCount,
      edrPoliciesCount,
      devices: intuneDevices,
    };
  }

  // Only overwrite when at least one of the three surfaces succeeded -
  // preserves the last-good result on a transient/permission failure rather
  // than replacing it with a confident-looking but empty one.
  if (asrRulesLive !== null) {
    base.asrRules = asrRulesLive;
  }

  if (secureScoreData) {
    base.secureScore = secureScoreData;
  }

  if (capabilitiesLive !== null) {
    base.capabilities = capabilitiesLive;
  }

  if (licenseSkusLive !== null) {
    base.licenseSkus = licenseSkusLive;
  }

  if (appRegistrationsLive !== null) {
    base.appRegistrations = appRegistrationsLive;
  }

  if (incidentsLive !== null) {
    base.incidents = incidentsLive;
  } else if (!base.incidents) {
    base.incidents = [];
  }

  // Each of the three mdoThreat fields comes from an independent source (EXO
  // for policies/tabl, Graph Security Alerts for alerts) and falls back to
  // whatever the previous snapshot had whenever this sync's fetch for that
  // field specifically didn't run or didn't return data.
  if (mailboxesLive !== null) {
    base.mailboxes = mailboxesLive;
  }
  if (emailForwardingLive !== null) {
    base.emailForwarding = emailForwardingLive;
  }
  if (transportRulesLive !== null) {
    base.mailflowTransportRules = transportRulesLive;
  }
  if (connectorsLive !== null) {
    base.mailflowConnectors = connectorsLive;
  }
  if (remoteDomainAutoForwardBlocked !== undefined && remoteDomainAutoForwardBlocked !== null) {
    base.remoteDomainAutoForwardBlocked = remoteDomainAutoForwardBlocked;
  }
  if (externalSenderTagEnabled !== undefined && externalSenderTagEnabled !== null) {
    base.externalSenderTagEnabled = externalSenderTagEnabled;
  }
  if (domainAuthLive !== null) {
    base.domainAuth = domainAuthLive;
  }
  if (groupsLive !== null) {
    base.groups = groupsLive;
  }
  if (groupExpirationPolicyEnabled !== undefined) {
    base.groupExpirationPolicyEnabled = groupExpirationPolicyEnabled;
  }
  if (groupSelfServiceCreationRestricted !== undefined) {
    base.groupSelfServiceCreationRestricted = groupSelfServiceCreationRestricted;
  }
  if (groupNamingPolicyEnabled !== undefined) {
    base.groupNamingPolicyEnabled = groupNamingPolicyEnabled;
  }
  if (sharePointLive !== null) {
    base.sharePoint = sharePointLive;
  }
  // Distinguish "never synced" (leave whatever the snapshot already had,
  // including undefined) from "synced but the Get-OrganizationConfig call
  // itself failed" (null - treated the same as never synced, since there's
  // nothing new to show) from an actual true/false result.
  if (mailboxAuditingEnabled !== undefined && mailboxAuditingEnabled !== null) {
    base.mailboxAuditingEnabled = mailboxAuditingEnabled;
  }

  base.mdoThreat = {
    policies: mdoPolicies !== null ? mdoPolicies : base.mdoThreat.policies,
    // A successful live fetch replaces the synced portion of the list, but
    // preserves any entry added locally while writes were disabled (or
    // before EXO was connected) - those never exist in the real Tenant
    // Allow/Block List, so a Get-TenantAllowBlockListItems fetch can never
    // return them, and replacing wholesale would silently delete them.
    // See tenant-store.addTablEntry, which is what sets isLocalOnly.
    tabl: mdoTabl !== null ? [...base.mdoThreat.tabl.filter((e) => e.isLocalOnly), ...mdoTabl] : base.mdoThreat.tabl,
    alerts: mdoAlerts !== null ? mdoAlerts : base.mdoThreat.alerts,
  };

  // Compute High Risk Threat Indicators from freshly aggregated data
  const unprotectedAdmins = (base.mfaAudit || []).filter(
    (u) => u.isAdmin && (u.isWeakAuth || !u.mfaRegistered)
  ).length;
  const highRiskApps = (base.appRegistrations || []).filter(
    (a) => a.riskCategory === "critical" || a.riskCategory === "high"
  ).length;

  base.highRiskThreatIndicators = {
    unprotectedAdminsCount: unprotectedAdmins,
    highRiskAppRegistrationsCount: highRiskApps,
  };

  return { snapshot: base };
}
