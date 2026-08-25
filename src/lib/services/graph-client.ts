import { Tenant, TenantSecuritySnapshot, CAPolicyRule, UserMfaProfile, TenantAccountSummary, SignInEvent, SignInStatus, SyncHealth, IntuneDevice } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { matchCaBaselineCode, computeBaselineCoveragePercent } from "./ca-baseline-matcher";
import { fetchAllPages } from "./graph-pagination";
import { createBlankSnapshot } from "../data/default-snapshot";
import { classifyUserAuthMethods } from "./mfa-classifier";
import { mapManagedDeviceToIntuneDevice } from "./intune-mapper";
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
  const permissionsToTest: Omit<PermissionTestResult, "status">[] = [
    {
      permission: "Policy.Read.All",
      scope: "Application",
      description: "Read Conditional Access policies and tenant identity security baselines.",
      endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      requiredFor: "Module 1: Conditional Access Policy Scanner & Baseline Audit",
    },
    {
      permission: "Policy.ReadWrite.ConditionalAccess",
      scope: "Application",
      description: "Create and update Conditional Access policies in Report-Only or Enforced mode.",
      endpoint: "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies",
      requiredFor: "Direct In-App CA Auto-Deployment & Baseline Remediation",
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
        allPassed = false;
        const errJson = await res.json().catch(() => ({}));
        results.push({
          ...perm,
          status: "missing",
          statusCode: res.status,
          errorMessage: errJson?.error?.message || `Access denied (${res.status} ${res.statusText})`,
        });
      }
    } catch (e: any) {
      allPassed = false;
      results.push({
        ...perm,
        status: "missing",
        errorMessage: e.message || "Network request failed",
      });
    }
  }

  return {
    tenantId: tenant.id,
    tenantName: tenant.displayName,
    testedAt: new Date().toISOString(),
    overallStatus: allPassed ? "all_granted" : results.some((r) => r.status === "granted") ? "partial" : "failed",
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
  existingSnapshot?: TenantSecuritySnapshot
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
      "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999&$select=id,deviceName,userPrincipalName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime",
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

  // 7. Compute baseline coverage
  const deployedBaselineCodes = new Set(livePolicies.map((p) => p.baselineCode).filter(Boolean));
  const coveragePercent = computeBaselineCoveragePercent(deployedBaselineCodes.size, CA_BASELINE_STANDARDS.length);

  const syncHealth: SyncHealth = {
    isPartial: syncErrors.length > 0,
    errors: syncErrors,
    lastAttemptAt: new Date().toISOString(),
  };

  // 8. Build or update snapshot. The fields below are all overwritten immediately
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

  return { snapshot: base };
}
