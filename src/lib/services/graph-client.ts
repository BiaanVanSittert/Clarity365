import { Tenant, TenantSecuritySnapshot, CAPolicyRule, UserMfaProfile, TenantAccountSummary, SignInEvent, SignInStatus } from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";

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

  const tokenEndpoint = `https://login.microsoftonline.com/${encodeURIComponent(credentials.tenantId)}/oauth2/v2.0/token`;
  const body = new URLSearchParams();
  body.append("client_id", credentials.clientId);
  body.append("client_secret", credentials.clientSecret);
  body.append("scope", "https://graph.microsoft.com/.default");
  body.append("grant_type", "client_credentials");

  try {
    const res = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    const data = await res.json();
    if (!res.ok || !data.access_token) {
      return { error: data.error_description || data.error || `Authentication failed with status ${res.status}` };
    }

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
      permission: "Organization.Read.All / Directory.Read.All",
      scope: "Application",
      description: "Read tenant SKU subscriptions, license tiers (e.g. Entra ID P2), and verified domains.",
      endpoint: "https://graph.microsoft.com/v1.0/organization",
      requiredFor: "Tenant Capability Detection & License SKU Matrix",
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
      const res = await fetch(perm.endpoint, {
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
    const res = await fetch("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

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

  // 1. Fetch Conditional Access Policies
  let livePolicies: CAPolicyRule[] = [];
  try {
    const caRes = await fetch("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", { headers });
    if (caRes.ok) {
      const caData = await caRes.json();
      if (caData.value && Array.isArray(caData.value)) {
        livePolicies = caData.value.map((p: any) => {
          const match = p.displayName.match(/(?:CA|CA-|\bCA\s*)(0[1-9]|10|[1-9])\b/i);
          let detectedCode: string | null = null;
          if (match) {
            const num = parseInt(match[1], 10);
            detectedCode = num < 10 ? `CA0${num}` : `CA${num}`;
          } else {
            const lower = p.displayName.toLowerCase();
            if (lower.includes("legacy") || lower.includes("basic auth") || lower.includes("activesync")) detectedCode = "CA01";
            else if (lower.includes("mfa") && (lower.includes("all users") || lower.includes("all employees") || lower.includes("all members"))) detectedCode = "CA02";
            else if ((lower.includes("mfa") || lower.includes("multifactor")) && (lower.includes("admin") || lower.includes("privileged") || lower.includes("global admin"))) detectedCode = "CA03";
            else if (lower.includes("guest") || lower.includes("external")) detectedCode = "CA04";
            else if (lower.includes("azure management") || lower.includes("portal") || lower.includes("powershell") || lower.includes("cli")) detectedCode = "CA05";
            else if (lower.includes("risky sign-in") || lower.includes("sign-in risk") || lower.includes("signin risk")) detectedCode = "CA06";
            else if (lower.includes("high-risk user") || lower.includes("user risk") || lower.includes("risky user")) detectedCode = "CA07";
            else if (lower.includes("untrusted countr") || lower.includes("geo") || lower.includes("location block") || lower.includes("foreign")) detectedCode = "CA08";
            else if (lower.includes("compliant device") || lower.includes("mdm") || lower.includes("hybrid") || lower.includes("intune compliant")) detectedCode = "CA09";
            else if (lower.includes("phishing-resistant") || lower.includes("fido2") || lower.includes("passwordless") || lower.includes("cba")) detectedCode = "CA10";
          }

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
      }
    }
  } catch (err) {
    console.error("[Graph Client] Error fetching CA policies:", err);
  }

  // 2. Fetch Users
  let usersList: TenantAccountSummary["users"] = [];
  try {
    const usersRes = await fetch("https://graph.microsoft.com/v1.0/users?$top=999&$select=id,displayName,userPrincipalName,accountEnabled,jobTitle,department,createdDateTime,assignedLicenses", { headers });
    if (usersRes.ok) {
      const usersData = await usersRes.json();
      if (usersData.value) {
        usersList = usersData.value.map((u: any) => {
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
      }
    }
  } catch (err) {
    console.error("[Graph Client] Error fetching users:", err);
  }

  // 3. Fetch Sign-In Logs
  let signInsList: SignInEvent[] = [];
  try {
    let signInsRes = await fetch("https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=250", { headers });
    if (!signInsRes.ok && signInsRes.status === 400) {
      signInsRes = await fetch("https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100", { headers });
    }
    if (signInsRes.ok) {
      const signInsData = await signInsRes.json();
      if (signInsData.value && Array.isArray(signInsData.value)) {
        signInsList = signInsData.value.map((s: any) => {
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
      }
    }
  } catch (err) {
    console.error("[Graph Client] Error fetching sign-in logs:", err);
  }

  // 4. Compute baseline coverage
  const deployedBaselineCodes = new Set(livePolicies.map((p) => p.baselineCode).filter(Boolean));
  const coveragePercent = Math.round((deployedBaselineCodes.size / CA_BASELINE_STANDARDS.length) * 100);

  // 5. Build or update snapshot
  const base = existingSnapshot || {
    tenant,
    capabilities: [
      { id: "cap-entra-p1", name: "Microsoft Entra ID", category: "Identity" as const, licensed: true, tier: "Active", description: "Conditional Access & Identity Management" },
      { id: "cap-intune", name: "Microsoft Intune", category: "Endpoint" as const, licensed: true, tier: "Active", description: "Endpoint & Compliance Management" },
      { id: "cap-mde", name: "Defender for Endpoint", category: "Endpoint" as const, licensed: true, tier: "Active", description: "Endpoint Threat Protection" },
      { id: "cap-mdo", name: "Defender for Office 365", category: "Threat" as const, licensed: true, tier: "Active", description: "Email & Collaboration Threat Protection" },
    ],
    secureScore: {
      currentScore: 480,
      maxScore: 650,
      percentage: 73.8,
      delta30Days: 2.5,
      delta90Days: 8.0,
      industryBenchmark: 62.0,
      history: [
        { date: "2026-05-20", score: 430, maxScore: 650, percentage: 66.1 },
        { date: "2026-06-20", score: 450, maxScore: 650, percentage: 69.2 },
        { date: "2026-07-20", score: 470, maxScore: 650, percentage: 72.3 },
        { date: "2026-08-20", score: 480, maxScore: 650, percentage: 73.8 },
      ],
      controls: [],
    },
    conditionalAccess: {
      baselineCoverageScore: coveragePercent,
      baselineDefinitions: CA_BASELINE_STANDARDS,
      policies: livePolicies,
    },
    signIns: signInsList,
    mfaAudit: [],
    accountClassification: {
      totalAccounts: usersList.length || 10,
      licensedUsersCount: usersList.filter((u) => u.classification === "licensed").length,
      unlicensedActiveCount: usersList.filter((u) => u.classification === "unlicensed_active").length,
      disabledAccountsCount: usersList.filter((u) => u.classification === "disabled").length,
      guestAccountsCount: 0,
      users: usersList,
    },
    mailboxes: [],
    emailForwarding: [],
    mdoThreat: { policies: [], tabl: [] },
    appRegistrations: [],
    intune: { antivirusPoliciesCount: 1, edrPoliciesCount: 1, compliantDevices: 10, nonCompliantDevices: 0, totalDevices: 10, devices: [] },
    groups: [],
    sharePoint: { tenantSharingLevel: "NewAndExistingGuests" as const, defaultLinkType: "Internal" as const, anonymousLinkExpirationDays: 30, totalStorageAllocatedTB: 10, totalStorageUsedTB: 2.1, sites: [] },
    highRiskThreatIndicators: {
      externalForwardingCount: 0,
      openSharePointSitesCount: 0,
      unprotectedAdminsCount: 0,
      highRiskAppRegistrationsCount: 0,
    },
  };

  base.tenant = { ...tenant, lastSyncTimestamp: new Date().toISOString(), connectionStatus: "healthy" };
  base.conditionalAccess = {
    baselineCoverageScore: coveragePercent,
    baselineDefinitions: CA_BASELINE_STANDARDS,
    policies: livePolicies.length > 0 ? livePolicies : base.conditionalAccess.policies,
  };

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

  return { snapshot: base };
}
