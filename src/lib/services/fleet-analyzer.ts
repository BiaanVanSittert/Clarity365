import {
  Tenant,
  TenantSecuritySnapshot,
  FleetTenantPosture,
  FleetPostureSummary,
  FleetTopFailingBaseline,
  FleetLicenseOptimizationSummary,
  FleetLicenseOptimizationItem,
  FleetSearchResultItem,
  TenantLicenseType,
  SecurityIncidentItem,
} from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { evaluateMdoBaseline } from "./mdo-baseline-matcher";
import { evaluateMailflowBaseline } from "./mailflow-baseline-matcher";
import { evaluateGroupsBaseline } from "./groups-baseline-matcher";
import { evaluateSharePointBaseline } from "./sharepoint-baseline-matcher";

// Estimated standard commercial Microsoft 365 licensing cost per seat per month (USD)
export const LICENSE_TIER_MONTHLY_COST: Record<TenantLicenseType, number> = {
  M365_E5: 57.0,
  M365_E3: 38.0,
  M365_BP: 22.0,
  M365_F3: 8.0,
  A5_EDU: 12.0,
};

export const DEFAULT_LICENSE_COST_USD = 25.0;

/**
 * Resolves the most accurate and recent interactive sign-in timestamp for a user.
 */
export function resolveUserLastSignIn(
  user: {
    id?: string;
    userPrincipalName: string;
    lastSignInDateTime?: string;
    createdDateTime?: string;
  },
  snapshot: TenantSecuritySnapshot
): {
  lastSignInDateTime?: string;
  daysInactive: number;
  isDormant: boolean;
} {
  const now = new Date("2026-08-30T12:00:00Z").getTime();
  const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;
  let latestSignInMs: number | null = null;

  if (user.lastSignInDateTime) {
    const t = new Date(user.lastSignInDateTime).getTime();
    if (!isNaN(t)) latestSignInMs = t;
  }

  // Cross-reference MFA audit profile
  const mfaUser = snapshot.mfaAudit?.find(
    (mu) => mu.userPrincipalName.toLowerCase() === user.userPrincipalName.toLowerCase()
  );
  if (mfaUser?.lastSignInDateTime) {
    const t = new Date(mfaUser.lastSignInDateTime).getTime();
    if (!isNaN(t) && (latestSignInMs === null || t > latestSignInMs)) {
      latestSignInMs = t;
    }
  }

  // Cross-reference recent sign-in events
  const userSignIns = (snapshot.signIns || []).filter(
    (s) =>
      s.userPrincipalName.toLowerCase() === user.userPrincipalName.toLowerCase() ||
      (user.id && s.userId === user.id)
  );
  for (const s of userSignIns) {
    const t = new Date(s.createdDateTime).getTime();
    if (!isNaN(t) && (latestSignInMs === null || t > latestSignInMs)) {
      latestSignInMs = t;
    }
  }

  if (latestSignInMs !== null) {
    const daysInactive = Math.max(0, Math.floor((now - latestSignInMs) / (24 * 60 * 60 * 1000)));
    return {
      lastSignInDateTime: new Date(latestSignInMs).toISOString(),
      daysInactive,
      isDormant: daysInactive > 90,
    };
  }

  // If no sign-in recorded, check account creation date
  if (user.createdDateTime) {
    const createdMs = new Date(user.createdDateTime).getTime();
    if (!isNaN(createdMs)) {
      const daysSinceCreation = Math.max(0, Math.floor((now - createdMs) / (24 * 60 * 60 * 1000)));
      return {
        lastSignInDateTime: undefined,
        daysInactive: daysSinceCreation,
        isDormant: daysSinceCreation > 90,
      };
    }
  }

  return {
    lastSignInDateTime: undefined,
    daysInactive: 0,
    isDormant: false,
  };
}

/**
 * Calculates monthly license waste and complete license inventory for a specific tenant:
 * 1. Licensed Shared Mailboxes (free under 50GB in M365 - direct license is pure waste).
 * 2. Inactive Licensed Users (>90 days without sign-in - recoverable waste).
 * 3. Disabled Accounts with Paid Licenses (departed staff still consuming seats - pure waste).
 * 4. Active Licensed Users (actively using paid non-free licenses).
 * 5. Orphaned Active Accounts (active accounts without license or hygiene - security risk).
 */
export function calculateTenantMonthlyWaste(snapshot: TenantSecuritySnapshot): {
  monthlyWasteUsd: number;
  items: FleetLicenseOptimizationItem[];
} {
  const tierCost = LICENSE_TIER_MONTHLY_COST[snapshot.tenant.tier] || DEFAULT_LICENSE_COST_USD;
  const items: FleetLicenseOptimizationItem[] = [];

  // 1. Licensed Shared Mailboxes (Direct license attached to shared mailbox)
  const licensedSharedMailboxes = (snapshot.mailboxes || []).filter(
    (m) => m.recipientType === "SharedMailbox" && m.hasDirectLicense
  );
  for (const mb of licensedSharedMailboxes) {
    items.push({
      id: `waste-shared-mb-${snapshot.tenant.id}-${mb.id}`,
      tenantId: snapshot.tenant.id,
      tenantName: snapshot.tenant.displayName,
      category: "licensed_shared_mailbox",
      title: `Direct License on Shared Mailbox: ${mb.displayName}`,
      description: `Shared mailbox '${mb.userPrincipalName}' has an assigned direct ${snapshot.tenant.tier.replace("_", " ")} license ($${tierCost}/mo). Shared mailboxes under 50GB do not require paid licenses.`,
      impactedIdentity: mb.userPrincipalName,
      displayName: mb.displayName,
      licenseSku: snapshot.tenant.tier,
      estimatedMonthlyCostUsd: tierCost,
      accountState: "shared_mailbox",
      remediationAction: "Unassign direct license from shared mailbox in Microsoft 365 Admin Center.",
      remediationModule: "mailboxes",
    });
  }

  // Process all tenant accounts from accountClassification
  const allUsers = snapshot.accountClassification?.users || [];

  for (const user of allUsers) {
    const { lastSignInDateTime, daysInactive, isDormant } = resolveUserLastSignIn(user, snapshot);
    const assignedSku = user.licenses?.[0] || snapshot.tenant.tier;

    // 2. Disabled Account holding Paid Licenses -> Pure Waste
    if ((!user.accountEnabled || user.classification === "disabled") && user.licenses && user.licenses.length > 0) {
      items.push({
        id: `waste-disabled-user-${snapshot.tenant.id}-${user.id}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        category: "disabled_licensed_user",
        title: `Disabled Account Holding Paid License: ${user.displayName}`,
        description: `Disabled account '${user.userPrincipalName}' still has paid license (${user.licenses.join(", ")}) assigned ($${tierCost}/mo). Licenses on departed/disabled users should be unassigned.`,
        impactedIdentity: user.userPrincipalName,
        displayName: user.displayName,
        department: user.department,
        licenseSku: assignedSku,
        estimatedMonthlyCostUsd: tierCost,
        lastSignInDateTime,
        daysInactive,
        accountState: "disabled",
        remediationAction: "Unassign license from disabled user in Microsoft 365 Admin Center.",
        remediationModule: "license_optimizer",
      });
      continue;
    }

    // 3. Licensed Active Users (Dormant vs Active)
    if (user.classification === "licensed" && user.accountEnabled) {
      if (isDormant) {
        items.push({
          id: `waste-inactive-user-${snapshot.tenant.id}-${user.id}`,
          tenantId: snapshot.tenant.id,
          tenantName: snapshot.tenant.displayName,
          category: "inactive_licensed_user",
          title: `Dormant Licensed Account: ${user.displayName}`,
          description: `User '${user.userPrincipalName}' has a paid license (${user.licenses?.join(", ") || snapshot.tenant.tier}) but has not signed in for ${daysInactive} days (>90d threshold).`,
          impactedIdentity: user.userPrincipalName,
          displayName: user.displayName,
          department: user.department,
          licenseSku: assignedSku,
          estimatedMonthlyCostUsd: tierCost,
          lastSignInDateTime,
          daysInactive,
          accountState: "dormant",
          remediationAction: "Reclaim unused license or convert account to shared mailbox/archive.",
          remediationModule: "license_optimizer",
        });
      } else {
        items.push({
          id: `active-licensed-user-${snapshot.tenant.id}-${user.id}`,
          tenantId: snapshot.tenant.id,
          tenantName: snapshot.tenant.displayName,
          category: "active_licensed_user",
          title: `Active Licensed User: ${user.displayName}`,
          description: `User '${user.userPrincipalName}' has active paid license (${user.licenses?.join(", ") || snapshot.tenant.tier}). Last sign-in: ${daysInactive === 0 ? "today" : `${daysInactive} days ago`}.`,
          impactedIdentity: user.userPrincipalName,
          displayName: user.displayName,
          department: user.department,
          licenseSku: assignedSku,
          estimatedMonthlyCostUsd: tierCost,
          lastSignInDateTime,
          daysInactive,
          accountState: "active",
          remediationAction: "Active licensed seat in good standing.",
          remediationModule: "license_optimizer",
        });
      }
      continue;
    }

    // 4. Orphaned Accounts (unlicensed active accounts with interactive login enabled)
    if (user.classification === "unlicensed_active" || (user.accountEnabled && (!user.licenses || user.licenses.length === 0) && user.classification !== "guest")) {
      items.push({
        id: `waste-orphaned-${snapshot.tenant.id}-${user.id}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        category: "orphaned_account",
        title: `Orphaned Active Account: ${user.displayName}`,
        description: `Active directory account '${user.userPrincipalName}' is enabled without assigned licenses or ownership governance.`,
        impactedIdentity: user.userPrincipalName,
        displayName: user.displayName,
        department: user.department,
        estimatedMonthlyCostUsd: 0, // Security risk
        lastSignInDateTime,
        daysInactive,
        accountState: "unlicensed",
        remediationAction: "Disable account or assign managed lifecycle policy in Entra ID.",
        remediationModule: "user_class",
      });
    }
  }

  // Total monthly waste is the sum of pure waste items: shared mailboxes + dormant accounts + disabled accounts with license
  const monthlyWasteUsd = items
    .filter((i) => i.category === "licensed_shared_mailbox" || i.category === "inactive_licensed_user" || i.category === "disabled_licensed_user")
    .reduce((sum, item) => sum + item.estimatedMonthlyCostUsd, 0);

  return { monthlyWasteUsd, items };
}

/**
 * Computes a weighted Composite Risk Score (0-100) for a tenant.
 * Higher score = higher security risk.
 */
export function computeTenantCompositeRiskScore(snapshot: TenantSecuritySnapshot): {
  score: number;
  level: "critical" | "high" | "medium" | "low";
  factors: Record<string, number>;
} {
  const totalUsers = Math.max(snapshot.accountClassification?.totalAccounts || 1, 1);
  const totalDevices = Math.max(snapshot.intune?.totalDevices || 0, 1);

  // 1. Secure Score Deficit (up to 30 points)
  const secureScorePct = snapshot.secureScore?.percentage || 0;
  const secureScoreDeficitPts = Math.min(30, Math.max(0, (100 - secureScorePct) * 0.3));

  // 2. Active High/Critical Incidents (up to 30 points)
  const criticalHighIncidents = (snapshot.incidents || []).filter(
    (i) => (i.severity === "critical" || i.severity === "high") && i.status !== "resolved"
  ).length;
  const incidentPts = Math.min(30, criticalHighIncidents * 12);

  // 3. Missing CA Baselines (up to 15 points)
  const deployedCodes = new Set(
    (snapshot.conditionalAccess?.policies || []).map((p) => p.baselineCode).filter(Boolean)
  );
  const missingCABaselines = Math.max(0, CA_BASELINE_STANDARDS.length - deployedCodes.size);
  const caPts = Math.min(15, missingCABaselines * 2.5);

  // 4. Weak / Missing MFA Ratio (up to 15 points)
  const weakMfaCount = (snapshot.mfaAudit || []).filter((m) => m.isWeakAuth || !m.mfaRegistered).length;
  const mfaRatio = weakMfaCount / totalUsers;
  const mfaPts = Math.min(15, Math.round(mfaRatio * 15));

  // 5. Non-Compliant Endpoint Ratio (up to 10 points)
  const nonCompliantDevs = (snapshot.intune?.devices || []).filter(
    (d) => d.complianceState === "noncompliant" || d.complianceState === "error"
  ).length;
  const devRatio = nonCompliantDevs / totalDevices;
  const devicePts = Math.min(10, Math.round(devRatio * 10));

  // 6. External Forwarding Rules (up to 10 points)
  const externalFwdCount = (snapshot.emailForwarding || []).filter((r) => r.isExternal && r.state === "Enabled").length;
  const fwdPts = Math.min(10, externalFwdCount * 3);

  const rawScore = secureScoreDeficitPts + incidentPts + caPts + mfaPts + devicePts + fwdPts;
  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  let level: "critical" | "high" | "medium" | "low" = "low";
  if (finalScore >= 70) level = "critical";
  else if (finalScore >= 45) level = "high";
  else if (finalScore >= 20) level = "medium";

  return {
    score: finalScore,
    level,
    factors: {
      secureScoreDeficit: Math.round(secureScoreDeficitPts),
      activeIncidents: incidentPts,
      missingCABaselines: Math.round(caPts),
      weakMfa: mfaPts,
      nonCompliantDevices: devicePts,
      externalForwarding: fwdPts,
    },
  };
}

/**
 * Analyzes failing baselines across the fleet and returns the most frequent policy gaps.
 */
export function aggregateFleetFailingBaselines(
  snapshots: TenantSecuritySnapshot[]
): FleetTopFailingBaseline[] {
  const failureMap = new Map<
    string,
    {
      code: string;
      name: string;
      category: "Identity" | "Exchange" | "Defender" | "Groups" | "SharePoint";
      failingTenantNames: Set<string>;
    }
  >();

  const recordFailure = (
    code: string,
    name: string,
    category: "Identity" | "Exchange" | "Defender" | "Groups" | "SharePoint",
    tenantName: string
  ) => {
    if (!failureMap.has(code)) {
      failureMap.set(code, {
        code,
        name,
        category,
        failingTenantNames: new Set(),
      });
    }
    failureMap.get(code)!.failingTenantNames.add(tenantName);
  };

  for (const snap of snapshots) {
    const tName = snap.tenant.displayName;

    // 1. CA Baselines (CA01 - CA10)
    const deployedCodes = new Set(
      (snap.conditionalAccess?.policies || []).map((p) => p.baselineCode).filter(Boolean)
    );
    for (const caStd of CA_BASELINE_STANDARDS) {
      if (!deployedCodes.has(caStd.code)) {
        recordFailure(caStd.code, caStd.name, "Identity", tName);
      }
    }

    // 2. MDO Baselines
    if (snap.mdoThreat?.policies) {
      const mdoResults = evaluateMdoBaseline(snap.mdoThreat.policies);
      for (const r of mdoResults.results) {
        if (!r.met) {
          recordFailure(r.code, `MDO Baseline Check ${r.code}`, "Defender", tName);
        }
      }
    }

    // 3. Mailflow Baselines
    if (snap.mailflowTransportRules) {
      const mfResults = evaluateMailflowBaseline({
        transportRules: snap.mailflowTransportRules,
        policies: snap.mdoThreat?.policies || [],
        connectors: snap.mailflowConnectors || [],
        remoteDomainAutoForwardBlocked: snap.remoteDomainAutoForwardBlocked,
        externalSenderTagEnabled: snap.externalSenderTagEnabled,
      });
      for (const r of mfResults.results) {
        if (!r.met) {
          recordFailure(r.code, `Mail Flow Check ${r.code}`, "Exchange", tName);
        }
      }
    }

    // 4. Groups Baselines
    if (snap.groups) {
      const grpResults = evaluateGroupsBaseline({
        groups: snap.groups,
        caExclusionGroupIds: new Set(
          (snap.conditionalAccess?.policies || []).flatMap((p) => p.conditions.users.excludeGroupIds || [])
        ),
        weakMfaUserPrincipalNamesLower: new Set(
          (snap.mfaAudit || [])
            .filter((u) => u.isWeakAuth || !u.mfaRegistered)
            .map((u) => u.userPrincipalName.toLowerCase())
        ),
        groupExpirationPolicyEnabled: snap.groupExpirationPolicyEnabled,
        groupSelfServiceCreationRestricted: snap.groupSelfServiceCreationRestricted,
        groupNamingPolicyEnabled: snap.groupNamingPolicyEnabled,
      });
      for (const r of grpResults.results) {
        if (!r.met) {
          recordFailure(r.code, `Groups Governance Check ${r.code}`, "Groups", tName);
        }
      }
    }

    // 5. SharePoint Baselines
    if (snap.sharePoint) {
      const spResults = evaluateSharePointBaseline({
        policy: snap.sharePoint,
        inactiveUserPrincipalNamesLower: new Set(
          (snap.accountClassification?.users || [])
            .filter((u) => u.classification === "disabled" || u.classification === "unlicensed_active")
            .map((u) => u.userPrincipalName.toLowerCase())
        ),
      });
      for (const r of spResults.results) {
        if (!r.met) {
          recordFailure(r.code, `SharePoint Security Check ${r.code}`, "SharePoint", tName);
        }
      }
    }
  }

  const list: FleetTopFailingBaseline[] = Array.from(failureMap.values()).map((entry) => ({
    code: entry.code,
    name: entry.name,
    category: entry.category,
    failingTenantsCount: entry.failingTenantNames.size,
    totalTenantsCount: snapshots.length,
    failingTenantNames: Array.from(entry.failingTenantNames),
  }));

  // Sort descending by failing tenants count
  return list.sort((a, b) => b.failingTenantsCount - a.failingTenantsCount);
}

/**
 * Computes the aggregated Fleet Posture Summary across all tenant snapshots.
 */
export function computeFleetPosture(
  tenants: Tenant[],
  snapshots: TenantSecuritySnapshot[]
): FleetPostureSummary {
  const snapshotMap = new Map(snapshots.map((s) => [s.tenant.id, s]));

  let totalManagedUsers = 0;
  let totalManagedDevices = 0;
  let totalSecureScoreSum = 0;
  let totalActiveIncidents = 0;
  let totalCriticalHighIncidents = 0;
  let tenantsAtCriticalRisk = 0;
  let totalMonthlyWasteUsd = 0;

  const fleetTenants: FleetTenantPosture[] = [];
  const allIncidents: (SecurityIncidentItem & { tenantId: string; tenantName: string })[] = [];

  for (const tenant of tenants) {
    const snap = snapshotMap.get(tenant.id);
    if (!snap) continue;

    const totalUsers = snap.accountClassification?.totalAccounts || 0;
    const licensedUsers = snap.accountClassification?.licensedUsersCount || 0;
    const unlicensedActive = snap.accountClassification?.unlicensedActiveCount || 0;
    const totalDevices = snap.intune?.totalDevices || 0;
    const nonCompliantDevices = (snap.intune?.devices || []).filter(
      (d) => d.complianceState === "noncompliant" || d.complianceState === "error"
    ).length;
    const isolatedDevices = (snap.intune?.devices || []).filter((d: any) => Boolean(d.isIsolated)).length;

    const deployedCodes = new Set(
      (snap.conditionalAccess?.policies || []).map((p) => p.baselineCode).filter(Boolean)
    );
    const missingCABaselines = Math.max(0, CA_BASELINE_STANDARDS.length - deployedCodes.size);
    const weakMfa = (snap.mfaAudit || []).filter((m) => m.isWeakAuth || !m.mfaRegistered).length;
    const extFwd = (snap.emailForwarding || []).filter((r) => r.isExternal && r.state === "Enabled").length;

    const activeIncidents = (snap.incidents || []).filter(
      (i) => i.status === "active" || i.status === "inProgress"
    ).length;
    const criticalHighIncidents = (snap.incidents || []).filter(
      (i) => (i.severity === "critical" || i.severity === "high") && i.status !== "resolved"
    ).length;

    const { score: compositeRiskScore, level: riskLevel } = computeTenantCompositeRiskScore(snap);
    const { monthlyWasteUsd } = calculateTenantMonthlyWaste(snap);

    totalManagedUsers += totalUsers;
    totalManagedDevices += totalDevices;
    totalSecureScoreSum += snap.secureScore?.percentage || 0;
    totalActiveIncidents += activeIncidents;
    totalCriticalHighIncidents += criticalHighIncidents;
    totalMonthlyWasteUsd += monthlyWasteUsd;
    if (riskLevel === "critical") tenantsAtCriticalRisk++;

    // Collect incidents for cross-tenant feed
    for (const inc of snap.incidents || []) {
      allIncidents.push({
        ...inc,
        tenantId: tenant.id,
        tenantName: tenant.displayName,
      });
    }

    fleetTenants.push({
      tenantId: tenant.id,
      displayName: tenant.displayName,
      defaultDomainName: tenant.defaultDomainName,
      tier: tenant.tier,
      connectionStatus: tenant.connectionStatus,
      isDemo: tenant.isDemo,
      lastSyncTimestamp: tenant.lastSyncTimestamp,
      secureScore: {
        current: snap.secureScore?.currentScore || 0,
        max: snap.secureScore?.maxScore || 100,
        percentage: snap.secureScore?.percentage || 0,
      },
      totalUsers,
      licensedUsers,
      unlicensedActiveUsers: unlicensedActive,
      totalDevices,
      nonCompliantDevices,
      isolatedDevices,
      missingCABaselinesCount: missingCABaselines,
      weakMfaCount: weakMfa,
      externalForwardingCount: extFwd,
      activeIncidentsCount: activeIncidents,
      criticalHighIncidentsCount: criticalHighIncidents,
      compositeRiskScore,
      riskLevel,
      monthlyEstimatedWasteUsd: monthlyWasteUsd,
    });
  }

  // Sort tenants by highest composite risk first
  fleetTenants.sort((a, b) => b.compositeRiskScore - a.compositeRiskScore);

  // Sort incidents by created date descending
  allIncidents.sort((a, b) => new Date(b.createdDateTime).getTime() - new Date(a.createdDateTime).getTime());

  const averageSecureScore =
    fleetTenants.length > 0 ? Math.round((totalSecureScoreSum / fleetTenants.length) * 10) / 10 : 0;

  const healthyTenantsCount = tenants.filter((t) => t.connectionStatus === "healthy").length;

  return {
    totalTenants: fleetTenants.length,
    healthyTenantsCount,
    totalManagedUsers,
    totalManagedDevices,
    averageSecureScore,
    totalActiveIncidents,
    totalCriticalHighIncidents,
    tenantsAtCriticalRisk,
    totalMonthlyEstimatedWasteUsd: totalMonthlyWasteUsd,
    tenants: fleetTenants,
    topFailingBaselines: aggregateFleetFailingBaselines(snapshots),
    recentCrossTenantIncidents: allIncidents.slice(0, 15),
  };
}

/**
 * Computes total license optimization items and dollar waste across all tenant snapshots.
 */
export function computeFleetLicenseWaste(
  snapshots: TenantSecuritySnapshot[]
): FleetLicenseOptimizationSummary {
  const allItems: FleetLicenseOptimizationItem[] = [];

  let wasteSharedMb = 0;
  let wasteInactiveUsers = 0;
  let wasteDisabledUsers = 0;
  let wasteOrphaned = 0;
  let wasteUnassigned = 0;
  let totalMonthlyLicensedCost = 0;

  for (const snap of snapshots) {
    const { items } = calculateTenantMonthlyWaste(snap);
    for (const item of items) {
      allItems.push(item);
      if (item.category === "licensed_shared_mailbox") {
        wasteSharedMb += item.estimatedMonthlyCostUsd;
        totalMonthlyLicensedCost += item.estimatedMonthlyCostUsd;
      } else if (item.category === "inactive_licensed_user") {
        wasteInactiveUsers += item.estimatedMonthlyCostUsd;
        totalMonthlyLicensedCost += item.estimatedMonthlyCostUsd;
      } else if (item.category === "disabled_licensed_user") {
        wasteDisabledUsers += item.estimatedMonthlyCostUsd;
        totalMonthlyLicensedCost += item.estimatedMonthlyCostUsd;
      } else if (item.category === "active_licensed_user") {
        totalMonthlyLicensedCost += item.estimatedMonthlyCostUsd;
      } else if (item.category === "orphaned_account") {
        wasteOrphaned += item.estimatedMonthlyCostUsd;
      } else if (item.category === "unassigned_license_sku") {
        wasteUnassigned += item.estimatedMonthlyCostUsd;
      }
    }
  }

  // Sort: pure waste items first, then by highest monthly cost descending
  allItems.sort((a, b) => {
    const isWasteA = a.category === "licensed_shared_mailbox" || a.category === "inactive_licensed_user" || a.category === "disabled_licensed_user";
    const isWasteB = b.category === "licensed_shared_mailbox" || b.category === "inactive_licensed_user" || b.category === "disabled_licensed_user";
    if (isWasteA && !isWasteB) return -1;
    if (!isWasteA && isWasteB) return 1;
    return b.estimatedMonthlyCostUsd - a.estimatedMonthlyCostUsd;
  });

  const totalMonthlyWasteUsd = wasteSharedMb + wasteInactiveUsers + wasteDisabledUsers + wasteUnassigned;
  const totalAnnualWasteUsd = totalMonthlyWasteUsd * 12;

  return {
    totalMonthlyWasteUsd,
    totalAnnualWasteUsd,
    totalMonthlyLicensedCostUsd: totalMonthlyLicensedCost,
    wasteByCategory: {
      licensedSharedMailboxes: wasteSharedMb,
      orphanedAccounts: wasteOrphaned,
      inactiveLicensedUsers: wasteInactiveUsers,
      disabledLicensedUsers: wasteDisabledUsers,
      unassignedSkus: wasteUnassigned,
    },
    items: allItems,
  };
}

/**
 * Fast universal search across all tenants in memory.
 * Matches: users, incidents, IP addresses, hashes, devices, app registrations, forwarding rules, and TABL items.
 */
export function searchAcrossFleet(
  snapshots: TenantSecuritySnapshot[],
  query: string,
  categoryFilter?: string
): FleetSearchResultItem[] {
  const q = (query || "").trim().toLowerCase();
  if (!q) return [];

  const results: FleetSearchResultItem[] = [];
  const MAX_RESULTS = 50;

  for (const snap of snapshots) {
    if (results.length >= MAX_RESULTS) break;
    const tId = snap.tenant.id;
    const tName = snap.tenant.displayName;

    // 1. Users
    if (!categoryFilter || categoryFilter === "user") {
      const seenUserIds = new Set<string>();

      for (const u of snap.accountClassification?.users || []) {
        if (results.length >= MAX_RESULTS) break;
        seenUserIds.add(u.id);
        seenUserIds.add(u.userPrincipalName.toLowerCase());
        if (
          u.userPrincipalName.toLowerCase().includes(q) ||
          u.displayName.toLowerCase().includes(q) ||
          (u.department && u.department.toLowerCase().includes(q))
        ) {
          results.push({
            id: `srch-usr-${tId}-${u.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "user",
            title: u.displayName,
            subtitle: `${u.userPrincipalName} • ${u.department || "No department"}`,
            matchField: u.userPrincipalName.toLowerCase().includes(q) ? "userPrincipalName" : "displayName",
            matchValue: u.userPrincipalName,
            statusPill: {
              status: u.accountEnabled ? (u.classification === "licensed" ? "pass" : "warn") : "fail",
              label: u.accountEnabled ? u.classification.replace("_", " ") : "disabled",
            },
            metadata: {
              accountEnabled: u.accountEnabled,
              classification: u.classification,
            },
            targetModule: "user_class",
          });
        }
      }

      // Also check mfaAudit users who might not be in the top 10 account sample
      for (const u of snap.mfaAudit || []) {
        if (results.length >= MAX_RESULTS) break;
        if (seenUserIds.has(u.id) || seenUserIds.has(u.userPrincipalName.toLowerCase())) continue;
        if (
          u.userPrincipalName.toLowerCase().includes(q) ||
          u.displayName.toLowerCase().includes(q) ||
          (u.department && u.department.toLowerCase().includes(q))
        ) {
          seenUserIds.add(u.userPrincipalName.toLowerCase());
          results.push({
            id: `srch-mfa-usr-${tId}-${u.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "user",
            title: u.displayName,
            subtitle: `${u.userPrincipalName} • ${u.department || u.jobTitle || "User"}`,
            matchField: u.userPrincipalName.toLowerCase().includes(q) ? "userPrincipalName" : "displayName",
            matchValue: u.userPrincipalName,
            statusPill: {
              status: u.accountEnabled ? (u.isWeakAuth ? "warn" : "pass") : "fail",
              label: u.isAdmin ? "Admin (MFA)" : "User (MFA)",
            },
            metadata: {
              accountEnabled: u.accountEnabled,
              isAdmin: u.isAdmin,
            },
            targetModule: "mfa_audit",
          });
        }
      }
    }

    // 2. Incidents
    if (!categoryFilter || categoryFilter === "incident") {
      for (const inc of snap.incidents || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          inc.displayName.toLowerCase().includes(q) ||
          inc.incidentId.toLowerCase().includes(q) ||
          inc.description.toLowerCase().includes(q) ||
          inc.mitreTechniques?.some((m) => m.toLowerCase().includes(q)) ||
          inc.impactedUsers?.some((u) => u.userPrincipalName.toLowerCase().includes(q) || u.displayName.toLowerCase().includes(q))
        ) {
          results.push({
            id: `srch-inc-${tId}-${inc.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "incident",
            title: `[${inc.incidentId}] ${inc.displayName}`,
            subtitle: `${inc.severity.toUpperCase()} • ${inc.impactedUsers?.map((u) => u.displayName).join(", ") || "No users"}`,
            matchField: inc.incidentId.toLowerCase().includes(q) ? "incidentId" : "displayName",
            matchValue: inc.displayName,
            statusPill: {
              status: inc.severity === "critical" ? "fail" : inc.severity === "high" ? "warn" : "info",
              label: inc.severity,
            },
            metadata: {
              status: inc.status,
              severity: inc.severity,
            },
            targetModule: "event_response",
          });
        }
      }
    }

    // 3. Sign-in Events & IP Addresses
    if (!categoryFilter || categoryFilter === "ip_address") {
      for (const sign of snap.signIns || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          sign.ipAddress.toLowerCase().includes(q) ||
          sign.userPrincipalName.toLowerCase().includes(q) ||
          sign.appDisplayName?.toLowerCase().includes(q) ||
          sign.location?.country?.toLowerCase().includes(q)
        ) {
          results.push({
            id: `srch-sign-${tId}-${sign.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "ip_address",
            title: `Sign-in from IP: ${sign.ipAddress}`,
            subtitle: `${sign.userPrincipalName} via ${sign.appDisplayName || "App"} (${sign.location?.city || "Unknown"}, ${sign.location?.country || "Unknown"})`,
            matchField: sign.ipAddress.toLowerCase().includes(q) ? "ipAddress" : "userPrincipalName",
            matchValue: sign.ipAddress,
            statusPill: {
              status: sign.status === "success" ? "pass" : sign.status === "ca_blocked" ? "warn" : "fail",
              label: sign.status.replace("_", " "),
            },
            metadata: {
              ip: sign.ipAddress,
              status: sign.status,
              risk: sign.riskLevel,
            },
            targetModule: "signin_logs",
          });
        }
      }
    }

    // 4. Intune Devices
    if (!categoryFilter || categoryFilter === "device") {
      for (const dev of snap.intune?.devices || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          dev.deviceName.toLowerCase().includes(q) ||
          dev.userPrincipalName.toLowerCase().includes(q) ||
          (dev.serialNumber && dev.serialNumber.toLowerCase().includes(q)) ||
          (dev.azureADDeviceId && dev.azureADDeviceId.toLowerCase().includes(q)) ||
          (dev.model && dev.model.toLowerCase().includes(q))
        ) {
          results.push({
            id: `srch-dev-${tId}-${dev.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "device",
            title: `Device: ${dev.deviceName}`,
            subtitle: `${dev.operatingSystem} ${dev.osVersion} • User: ${dev.userPrincipalName}`,
            matchField: dev.deviceName.toLowerCase().includes(q) ? "deviceName" : "userPrincipalName",
            matchValue: dev.deviceName,
            statusPill: {
              status: dev.complianceState === "compliant" ? "pass" : "fail",
              label: dev.complianceState,
            },
            metadata: {
              os: dev.operatingSystem,
              compliance: dev.complianceState,
              isIsolated: Boolean((dev as any).isIsolated),
            },
            targetModule: "intune",
          });
        }
      }
    }

    // 5. App Registrations & OAuth Permissions
    if (!categoryFilter || categoryFilter === "app_registration") {
      for (const app of snap.appRegistrations || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          app.displayName.toLowerCase().includes(q) ||
          app.appId.toLowerCase().includes(q) ||
          app.publisher?.toLowerCase().includes(q) ||
          app.highPrivilegePermissions?.some((p) => p.toLowerCase().includes(q))
        ) {
          results.push({
            id: `srch-app-${tId}-${app.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "app_registration",
            title: `App: ${app.displayName}`,
            subtitle: `App ID: ${app.appId} • ${app.highPrivilegePermissions?.length || 0} high-privilege scopes`,
            matchField: app.displayName.toLowerCase().includes(q) ? "displayName" : "appId",
            matchValue: app.displayName,
            statusPill: {
              status: app.riskCategory === "critical" ? "fail" : app.riskCategory === "high" ? "warn" : "info",
              label: `${app.riskCategory} risk`,
            },
            metadata: {
              appId: app.appId,
              risk: app.riskCategory,
            },
            targetModule: "app_regs",
          });
        }
      }
    }

    // 6. Email Forwarding Rules
    if (!categoryFilter || categoryFilter === "forwarding_rule") {
      for (const fwd of snap.emailForwarding || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          fwd.forwardingAddress.toLowerCase().includes(q) ||
          fwd.name.toLowerCase().includes(q) ||
          (fwd.mailboxOwner && fwd.mailboxOwner.toLowerCase().includes(q))
        ) {
          results.push({
            id: `srch-fwd-${tId}-${fwd.id}`,
            tenantId: tId,
            tenantName: tName,
            category: "forwarding_rule",
            title: `Forwarding Rule: ${fwd.name}`,
            subtitle: `Forwards to ${fwd.forwardingAddress} (${fwd.isExternal ? "EXTERNAL TARGET" : "Internal"})`,
            matchField: fwd.forwardingAddress.toLowerCase().includes(q) ? "forwardingAddress" : "name",
            matchValue: fwd.forwardingAddress,
            statusPill: {
              status: fwd.isExternal ? "fail" : "pass",
              label: fwd.isExternal ? "External Target" : "Internal",
            },
            metadata: {
              isExternal: fwd.isExternal,
              state: fwd.state,
            },
            targetModule: "forwarding",
          });
        }
      }
    }

    // 7. TABL Entries & Threat Hashes
    if (!categoryFilter || categoryFilter === "file_hash" || categoryFilter === "tabl") {
      for (const tabl of snap.mdoThreat?.tabl || []) {
        if (results.length >= MAX_RESULTS) break;
        if (
          tabl.value.toLowerCase().includes(q) ||
          (tabl.notes && tabl.notes.toLowerCase().includes(q)) ||
          tabl.entryType.toLowerCase().includes(q)
        ) {
          results.push({
            id: `srch-tabl-${tId}-${tabl.id}`,
            tenantId: tId,
            tenantName: tName,
            category: tabl.entryType === "file_hash" ? "file_hash" : "tabl",
            title: `TABL ${tabl.listType.toUpperCase()}: ${tabl.value}`,
            subtitle: `${tabl.entryType.toUpperCase()} • Reason: ${tabl.notes || "No notes"}`,
            matchField: "value",
            matchValue: tabl.value,
            statusPill: {
              status: tabl.listType === "block" ? "fail" : "pass",
              label: `${tabl.listType} list`,
            },
            metadata: {
              listType: tabl.listType,
              entryType: tabl.entryType,
            },
            targetModule: "mdo_tabl",
          });
        }
      }
    }
  }

  return results;
}
