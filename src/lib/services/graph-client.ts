import { Tenant, TenantSecuritySnapshot, CAPolicyRule, UserMfaProfile, TenantAccountSummary, SignInEvent, SignInStatus, SyncHealth, IntuneDevice, TenantSecureScore, MdoThreatPolicy, TablEntry, MdoThreatAlert, MailboxItem, EmailForwardingRule, MailflowTransportRule, DomainAuthStatus, MailflowConnector } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { matchCaBaselineCode, computeBaselineCoveragePercent } from "./ca-baseline-matcher";
import { fetchAllPages } from "./graph-pagination";
import { createBlankSnapshot } from "../data/default-snapshot";
import { classifyUserAuthMethods } from "./mfa-classifier";
import { mapManagedDeviceToIntuneDevice } from "./intune-mapper";
import { mapSecureScoreControl, buildSecureScoreHistory, computeScoreDelta, extractIndustryBenchmark } from "./secure-score-mapper";
import { fetchMdoPoliciesAndTabl, fetchMailflowData, fetchAcceptedDomainsAndDkim } from "./exo-client";
import { mapMdoAlert } from "./mdo-alert-mapper";
import { checkSpfRecord, checkDmarcRecord } from "./domain-dns-checker";
import { graphFetch } from "./graph-fetch";

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

export interface PermissionTestResult {
  permission: string;
  scope: "Application" | "Delegated";
  description: string;
  endpoint: string;
  status: "granted" | "missing" | "untested";
  statusCode?: number;
  errorMessage?: string;
  requiredFor: string;
  // True only for permissions that let Clarity365 create/modify/delete data in
  // the live tenant, not just read it — flagged distinctly in the Permissions
  // UI so granting it is a conscious choice, not lost among read-only scopes.
  isWriteAccess?: boolean;
  // True for a permission the app doesn't need to function — it unlocks one
  // additional write-capable feature on top of the read-only reporting this
  // app already provides without it. Excluded from the pass/fail rollup in
  // overallStatus so declining it (choosing read-only/reporting-only mode)
  // never shows as a problem needing attention.
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
      { timeoutMs: 10_000 } // fail fast — the whole sync is worthless without a token
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
  // Ordered read-only first, write-capable last — Policy.ReadWrite.ConditionalAccess
  // is the only write permission this app ever requests, and it's optional: every
  // other permission below already gives Clarity365 full audit/reporting coverage
  // (including generating a copy-pasteable PowerShell script for CA baseline gaps)
  // without it. Granting it additionally enables one specific feature — in-app
  // one-click auto-deployment — rather than being required for the app to work.
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
      permission: "DeviceManagementManagedDevices.Read.All",
      scope: "Application",
      description: "Read Intune-managed device inventory, compliance state, and encryption status.",
      endpoint: "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
      requiredFor: "Module 10: Intune Endpoint Security",
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
      permission: "Policy.ReadWrite.ConditionalAccess",
      scope: "Application",
      description:
        "Optional — only needed to auto-deploy CA baseline policies directly from Clarity365. Without it, Policy.Read.All above still gives full audit/reporting coverage, and Clarity365 generates a PowerShell script you can run manually instead.",
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
        headers: { Authorization: `Bearer ${token}` },
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
  // excluded from this rollup entirely — declining an optional write permission
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
      // A network exception here is ambiguous — the POST may have already reached
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
      const detectedCode = matchCaBaselineCode(p);
      const baselineDef = CA_BASELINE_STANDARDS.find((b) => b.code === detectedCode);

      return {
        id: p.id,
        name: p.displayName,
        baselineCode: detectedCode,
        baselineTitle: baselineDef?.name,
        state: p.state as any,
        modifiedDateTime: p.modifiedDateTime || new Date().toISOString(),
        createdDateTime: p.createdDateTime || new Date().toISOString(),
        grantControls: p.grantControls?.builtInControls || [],
        conditions: {
          users: {
            include: p.conditions?.users?.includeUsers || p.conditions?.users?.includeRoles || [],
            exclude: p.conditions?.users?.excludeUsers || [],
          },
          applications: {
            include: p.conditions?.applications?.includeApplications || [],
            exclude: p.conditions?.applications?.excludeApplications || [],
          },
          clientAppTypes: p.conditions?.clientAppTypes || [],
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
      "https://graph.microsoft.com/v1.0/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,assignedLicenses",
      headers
    );
    if (usersResult.error) syncErrors.push(`Users: ${usersResult.error}`);

    usersList = usersResult.items.map((u: any) => {
      const hasLicense = u.assignedLicenses && u.assignedLicenses.length > 0;
      const isEnabled = u.accountEnabled !== false;
      let classification: "licensed" | "unlicensed_active" | "disabled" | "guest" = "licensed";

      if (!isEnabled) {
        classification = "disabled";
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
          lastSignInDateTime: new Date().toISOString(),
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
          lastSignInDateTime: userSignIns[0]?.createdDateTime || new Date().toISOString(),
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
      "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999&$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,model,manufacturer,serialNumber,imei,enrolledDateTime,managementAgent,ownerType,deviceEnrollmentType,totalStorageSpaceInBytes,freeStorageSpaceInBytes,deviceCategoryDisplayName,azureADDeviceId,jailBroken,complianceGracePeriodExpirationDateTime,wiFiMacAddress",
      headers
    );
    if (devicesResult.error) syncErrors.push(`Intune devices: ${devicesResult.error}`);
    intuneDevices = devicesResult.items.map(mapManagedDeviceToIntuneDevice);
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune devices:", err);
    syncErrors.push(`Intune devices: ${err.message || "Unexpected error while processing devices."}`);
  }

  // 6. Fetch Intune Endpoint Security policy counts (tenant-wide aggregates,
  // not per-device). Endpoint Security "Intents" is a Graph beta surface —
  // category matching here is best-effort and worth confirming against a
  // real tenant; a failure here doesn't block the device inventory above.
  let antivirusPoliciesCount = 0;
  let edrPoliciesCount = 0;
  try {
    const intentsResult = await fetchAllPages<any>(
      "https://graph.microsoft.com/beta/deviceManagement/intents?$expand=categories",
      headers
    );
    if (intentsResult.error) syncErrors.push(`Intune Endpoint Security policies: ${intentsResult.error}`);
    intentsResult.items.forEach((intent: any) => {
      const categoryNames: string[] = (intent.categories || []).map((c: any) => (c.displayName || "").toLowerCase());
      if (categoryNames.some((c) => c.includes("antivirus"))) antivirusPoliciesCount++;
      if (categoryNames.some((c) => c.includes("detection and response") || c.includes("edr"))) edrPoliciesCount++;
    });
  } catch (err: any) {
    console.error("[Graph Client] Error fetching Intune Endpoint Security policies:", err);
    syncErrors.push(`Intune Endpoint Security policies: ${err.message || "Unexpected error while processing policies."}`);
  }

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

  // 8. Fetch MDO Policies & TABL via Exchange Online (see exo-client.ts —
  // Defender for Office 365 policies aren't reachable via standard Graph).
  // Skipped silently (not pushed as a sync error) if Exchange Online hasn't
  // been connected yet, since that's a separate, optional credential from
  // the Graph client secret used everywhere else — its absence isn't a
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
  // a plain Graph client-secret call, same as Secure Score/Intune) — useful
  // even for a tenant that hasn't connected EXO at all. Scoped to the last 30
  // days to match the "Threats Detected (30d)" framing in the UI. Exact OData
  // filter syntax/field names below are based on the documented alerts_v2
  // schema — worth confirming against a live tenant, same caveat as
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
  // Gated the same way as MDO policies above — skipped silently if EXO isn't
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
      // information — Get-Mailbox itself has no license concept.
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
  // every accepted domain, independent of any Microsoft 365 credential —
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

  // 9. Compute baseline coverage
  const deployedBaselineCodes = new Set(livePolicies.map((p) => p.baselineCode).filter(Boolean));
  const coveragePercent = computeBaselineCoveragePercent(deployedBaselineCodes.size, CA_BASELINE_STANDARDS.length);

  const syncHealth: SyncHealth = {
    isPartial: syncErrors.length > 0,
    errors: syncErrors,
    lastAttemptAt: new Date().toISOString(),
  };

  // 10. Build or update snapshot. The fields below are all overwritten immediately
  // after with the data just fetched — createBlankSnapshot only needs to supply a
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
      guestAccountsCount: 0,
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

  if (secureScoreData) {
    base.secureScore = secureScoreData;
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
  // Distinguish "never synced" (leave whatever the snapshot already had,
  // including undefined) from "synced but the Get-OrganizationConfig call
  // itself failed" (null — treated the same as never synced, since there's
  // nothing new to show) from an actual true/false result.
  if (mailboxAuditingEnabled !== undefined && mailboxAuditingEnabled !== null) {
    base.mailboxAuditingEnabled = mailboxAuditingEnabled;
  }

  base.mdoThreat = {
    policies: mdoPolicies !== null ? mdoPolicies : base.mdoThreat.policies,
    // A successful live fetch replaces the synced portion of the list, but
    // preserves any entry added locally while writes were disabled (or
    // before EXO was connected) — those never exist in the real Tenant
    // Allow/Block List, so a Get-TenantAllowBlockListItems fetch can never
    // return them, and replacing wholesale would silently delete them.
    // See tenant-store.addTablEntry, which is what sets isLocalOnly.
    tabl: mdoTabl !== null ? [...base.mdoThreat.tabl.filter((e) => e.isLocalOnly), ...mdoTabl] : base.mdoThreat.tabl,
    alerts: mdoAlerts !== null ? mdoAlerts : base.mdoThreat.alerts,
  };

  return { snapshot: base };
}
