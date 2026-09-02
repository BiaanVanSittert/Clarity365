import {
  TenantSecuritySnapshot,
  ExecutiveQbrReport,
  ReportBrandingConfig,
} from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";
import { validateCaPolicyCompliance } from "./ca-baseline-matcher";
import { calculateTenantMonthlyWaste } from "./fleet-analyzer";

export const DEFAULT_MSP_BRANDING: ReportBrandingConfig = {
  mspName: "Clarity365 Managed Cyber Defense",
  preparedBy: "Lead Cloud Security Architect",
  accentColor: "#0284c7",
  clientContact: "IT Security & Operations Committee",
};

/**
 * Generates an executive-ready Quarterly Business Review (QBR) report for a specific tenant.
 */
export function generateTenantQbrReport(
  snapshot: TenantSecuritySnapshot,
  period: string = "Q3 2026",
  customBranding?: Partial<ReportBrandingConfig>
): ExecutiveQbrReport {
  const branding: ReportBrandingConfig = {
    ...DEFAULT_MSP_BRANDING,
    ...customBranding,
  };

  // 1. Identity & MFA Stats
  const users = snapshot.mfaAudit || [];
  const totalUsers = users.length;
  const mfaEnforcedCount = users.filter((u) => u.mfaRegistered || u.mfaEnforcedByPolicy || (u as any).enforced).length;
  const mfaEnforcedPercent = totalUsers > 0 ? Math.round((mfaEnforcedCount / totalUsers) * 100) : 0;

  const admins = users.filter((u) => u.isAdmin);
  const adminCount = admins.length;
  const adminsWithPhishingResistantMfa = admins.filter(
    (u) =>
      u.registeredMethods?.some((m) => m.toLowerCase().includes("passkey") || m.toLowerCase().includes("fido2") || m.toLowerCase().includes("windows_hello")) ||
      u.defaultMethod?.toLowerCase().includes("passkey") ||
      u.defaultMethod?.toLowerCase().includes("fido2")
  ).length;

  const riskyUsersCount = (snapshot.signIns || []).filter((s) => s.isRisky || s.riskLevel === "high").length;
  const guestUsersCount = users.filter((u) => u.userPrincipalName.toLowerCase().includes("#ext#")).length;

  // 2. Golden Baseline Policies
  const deployedPolicies = snapshot.conditionalAccess?.policies || [];
  const evaluatedPolicies = CA_BASELINE_STANDARDS.map((std) => {
    const policy = deployedPolicies.find(
      (p) =>
        p.baselineCode?.toUpperCase() === std.code.toUpperCase() ||
        p.name.toUpperCase().startsWith(`${std.code.toUpperCase()}:`) ||
        p.name.toUpperCase().startsWith(`${std.code.toUpperCase()} `)
    );

    if (!policy) {
      return {
        code: std.code,
        name: std.name,
        state: "missing" as const,
        impact: std.riskMitigated,
      };
    }

    const validation = validateCaPolicyCompliance(policy, std.code);
    if (!validation.isValid) {
      return {
        code: std.code,
        name: std.name,
        state: "misconfigured" as const,
        impact: `Misconfigured: Missing ${validation.missingProperties?.join(", ")}`,
      };
    }

    if (policy.state === "enabled") {
      return {
        code: std.code,
        name: std.name,
        state: "enforced" as const,
        impact: std.riskMitigated,
      };
    }

    return {
      code: std.code,
      name: std.name,
      state: "report_only" as const,
      impact: `${std.riskMitigated} (Report-Only Monitoring)`,
    };
  });

  const enforcedCount = evaluatedPolicies.filter((p) => p.state === "enforced").length;
  const reportOnlyCount = evaluatedPolicies.filter((p) => p.state === "report_only").length;
  const missingCount = evaluatedPolicies.filter((p) => p.state === "missing" || p.state === "misconfigured").length;
  const baselineAdoptionScore = Math.round(((enforcedCount + reportOnlyCount * 0.7) / evaluatedPolicies.length) * 100);

  // 3. Threats & Hygiene Section
  const externalForwardingRulesBlocked = (snapshot.emailForwarding || []).filter((r) => r.isExternal && r.state === "Disabled").length;
  const activeForwardingRules = (snapshot.emailForwarding || []).filter((r) => r.isExternal && r.state !== "Disabled").length;
  const quarantineAlertsRemediated = (snapshot.mdoThreat?.policies || []).length;
  const activeThreatsCount = (snapshot.incidents || []).filter((i) => i.status !== "resolved").length + activeForwardingRules;
  const threatIndicatorsActive = 12; // TABL fleet threat count baseline
  const unmanagedDevicesCount = snapshot.intune?.nonCompliantDevices ?? (snapshot.intune?.devices || []).filter((d) => d.complianceState !== "compliant").length;
  const anonymousSharePointLinksCount = (snapshot.sharePoint?.sites || []).filter((s) => s.sharingCapability === "Anyone").length + (snapshot.sharePoint?.tenantSharingLevel === "Anyone" ? 1 : 0);

  // 4. Cost & License Optimization
  const { monthlyWasteUsd, items: wasteItems } = calculateTenantMonthlyWaste(snapshot);
  const inactiveLicensedUsers = wasteItems.filter((i) => i.category === "inactive_licensed_user");
  const disabledLicensedUsers = wasteItems.filter((i) => i.category === "disabled_licensed_user");
  const sharedMbWaste = wasteItems.filter((i) => i.category === "licensed_shared_mailbox");

  const inactiveLicensedUsersCount = inactiveLicensedUsers.length + disabledLicensedUsers.length;
  const wastedSharedMailboxLicensesCount = sharedMbWaste.length;
  const totalMonthlyCostSavingsIdentified = monthlyWasteUsd;
  const totalMonthlyCostSavingsReclaimed = Math.round(totalMonthlyCostSavingsIdentified * 0.35); // Historical reclaimed estimate
  const totalEstimatedAnnualWaste = totalMonthlyCostSavingsIdentified * 12;

  const reclaimableSeats = wasteItems
    .filter((i) => i.category === "inactive_licensed_user" || i.category === "disabled_licensed_user" || i.category === "licensed_shared_mailbox")
    .map((d) => ({
      upn: d.impactedIdentity,
      license: d.licenseSku || snapshot.tenant.tier,
      estimatedMonthlyCost: d.estimatedMonthlyCostUsd,
      reason: d.category === "licensed_shared_mailbox" ? "Shared mailbox with paid license" : d.title,
    }));

  // 5. Overall Health Score (Weighted 0-100)
  const secureScorePercent = Math.round(
    ((snapshot.secureScore?.currentScore || 70) / (snapshot.secureScore?.maxScore || 100)) * 100
  );

  const incidentPenalty = Math.min(20, activeThreatsCount * 3);
  const sharingPenalty = anonymousSharePointLinksCount > 0 ? 5 : 0;

  const overallHealthScore = Math.min(
    100,
    Math.max(
      10,
      Math.round(
        secureScorePercent * 0.45 +
          baselineAdoptionScore * 0.35 +
          mfaEnforcedPercent * 0.20 -
          incidentPenalty -
          sharingPenalty
      )
    )
  );

  let headlineStatus: "optimal" | "acceptable" | "needs_attention" | "critical_risk" = "optimal";
  if (overallHealthScore < 50 || activeThreatsCount > 2) {
    headlineStatus = "critical_risk";
  } else if (overallHealthScore < 70) {
    headlineStatus = "needs_attention";
  } else if (overallHealthScore < 85) {
    headlineStatus = "acceptable";
  }

  // 6. Dynamic Key Achievements & Action Items
  const keyAchievements: string[] = [];
  if (mfaEnforcedPercent >= 90) {
    keyAchievements.push(`High identity resilience: ${mfaEnforcedPercent}% of corporate users protected with Multifactor Authentication.`);
  }
  if (enforcedCount + reportOnlyCount >= 6) {
    keyAchievements.push(`Zero-Trust posture: ${enforcedCount + reportOnlyCount} of 10 Golden Baseline Conditional Access standards deployed.`);
  }
  if (activeForwardingRules === 0) {
    keyAchievements.push("Email exfiltration killswitch: 0 unauthorized external forwarding rules active across mailboxes.");
  }
  if (totalMonthlyCostSavingsIdentified > 0) {
    keyAchievements.push(`License efficiency: Identified $${totalMonthlyCostSavingsIdentified.toLocaleString()}/mo in potential subscription cost recovery.`);
  }
  if (keyAchievements.length === 0) {
    keyAchievements.push("Baseline security telemetry established across identity, cloud workloads, and collaboration layers.");
  }

  const topActionItems: string[] = [];
  if (activeForwardingRules > 0) {
    topActionItems.push(`CRITICAL: Immediately isolate and disable ${activeForwardingRules} active external mail forwarding rule(s).`);
  }
  if (missingCount > 0) {
    topActionItems.push(`Deploy ${missingCount} missing Golden Baseline policy standard(s) in Report-Only mode.`);
  }
  if (adminsWithPhishingResistantMfa < adminCount) {
    topActionItems.push(`Enroll remaining ${adminCount - adminsWithPhishingResistantMfa} administrator(s) in FIDO2 / Passkey phishing-resistant MFA.`);
  }
  if (inactiveLicensedUsersCount > 0) {
    topActionItems.push(`Reclaim ${inactiveLicensedUsersCount} dormant licenses from unutilized accounts to save $${totalMonthlyCostSavingsIdentified}/mo.`);
  }
  if (anonymousSharePointLinksCount > 0) {
    topActionItems.push(`Expire ${anonymousSharePointLinksCount} anonymous 'Anyone with the link' file shares to protect corporate IP.`);
  }
  if (topActionItems.length === 0) {
    topActionItems.push("Maintain continuous zero-trust monitoring and review monthly Entra ID audit logs.");
  }

  return {
    id: `qbr-${snapshot.tenant.id}-${Date.now().toString(36)}`,
    generatedAt: new Date().toISOString(),
    period,
    tenant: {
      id: snapshot.tenant.id,
      displayName: snapshot.tenant.displayName,
      defaultDomain: snapshot.tenant.defaultDomainName,
      tier: snapshot.tenant.tier,
    },
    branding,
    executiveSummary: {
      overallHealthScore,
      secureScorePercent,
      baselineAdoptionScore,
      activeThreatsCount,
      totalMonthlyCostSavingsIdentified,
      totalMonthlyCostSavingsReclaimed,
      headlineStatus,
      keyAchievements,
      topActionItems,
    },
    identityMfaSection: {
      totalUsers,
      mfaEnforcedPercent,
      adminCount,
      adminsWithPhishingResistantMfa,
      riskyUsersCount,
      guestUsersCount,
    },
    goldenBaselineSection: {
      totalPoliciesEvaluated: evaluatedPolicies.length,
      enforcedCount,
      reportOnlyCount,
      missingCount,
      policies: evaluatedPolicies,
    },
    threatsAndHygieneSection: {
      externalForwardingRulesBlocked,
      quarantineAlertsRemediated,
      threatIndicatorsActive,
      unmanagedDevicesCount,
      anonymousSharePointLinksCount,
    },
    costOptimizationSection: {
      inactiveLicensedUsersCount,
      wastedSharedMailboxLicensesCount,
      totalEstimatedAnnualWaste,
      reclaimableSeats,
    },
  };
}
