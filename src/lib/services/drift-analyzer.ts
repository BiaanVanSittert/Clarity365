import {
  TenantSecuritySnapshot,
  GoldenBaselineTemplate,
  TenantDriftFinding,
  TenantDriftAssessment,
  FleetDriftSummary,
  CAPolicyRule,
} from "../types";
import { CA_BASELINE_STANDARDS } from "../data/baseline-definitions";

/**
 * The standard default MSP Golden Baseline Template.
 * Represents enterprise-grade security hardening defaults for Microsoft 365.
 */
export const DEFAULT_GOLDEN_BASELINE: GoldenBaselineTemplate = {
  id: "msp-golden-baseline-v1",
  name: "Clarity365 MSP Golden Standard",
  description: "Enterprise Zero-Trust baseline: CA01-CA10, external forwarding killswitches, mailbox audit logging, and DKIM enforcement.",
  version: "1.2.0",
  updatedAt: "2026-08-30T12:00:00Z",
  caPolicies: [
    { code: "CA01", name: "Block legacy authentication", requiredState: "reportOnly" },
    { code: "CA02", name: "Require MFA for all users", requiredState: "reportOnly" },
    { code: "CA03", name: "Require MFA for all administrators", requiredState: "reportOnly" },
    { code: "CA04", name: "Block access from untrusted locations", requiredState: "reportOnly" },
    { code: "CA05", name: "Require compliant devices for cloud apps", requiredState: "reportOnly" },
    { code: "CA06", name: "Require MFA for high-risk sign-ins", requiredState: "reportOnly", requiresEntraP2: true },
    { code: "CA07", name: "Require password reset for high-risk users", requiredState: "reportOnly", requiresEntraP2: true },
    { code: "CA08", name: "Block unmanaged device desktop client downloads", requiredState: "reportOnly" },
    { code: "CA09", name: "Require phishing-resistant MFA for sensitive roles", requiredState: "reportOnly" },
    { code: "CA10", name: "Require continuous access evaluation & short sessions", requiredState: "reportOnly" },
  ],
  requireExternalForwardingBlocked: true,
  requireMailboxAuditLogging: true,
  requireDkimSigning: true,
  requireModernAuthOnly: true,
  minimumSecureScore: 60,
};

/**
 * Checks if a tenant snapshot has Entra ID P2 capability
 */
export function tenantHasEntraP2(snapshot: TenantSecuritySnapshot): boolean {
  return Boolean(
    snapshot.capabilities?.some(
      (c) =>
        c.licensed &&
        (c.id === "cap-entra-p2" ||
          c.name.toLowerCase().includes("entra id p2") ||
          c.name.toLowerCase().includes("azure ad premium p2") ||
          c.name.toLowerCase().includes("identity protection"))
    ) ||
    snapshot.tenant.tier === "M365_E5" ||
    (snapshot.tenant.tier as string) === "Microsoft 365 E5" ||
    (snapshot.tenant.tier as string) === "EMS_E5"
  );
}

/**
 * Evaluates a single tenant security snapshot against the Golden Baseline Template.
 * Computes granular drift findings, alignment percentage (0-100%), and overall status.
 */
export function evaluateTenantDrift(
  snapshot: TenantSecuritySnapshot,
  template: GoldenBaselineTemplate = DEFAULT_GOLDEN_BASELINE
): TenantDriftAssessment {
  const findings: TenantDriftFinding[] = [];
  let evaluatedRulesCount = 0;
  let passingRulesCount = 0;

  const deployedPolicies = snapshot.conditionalAccess?.policies || [];
  const hasP2 = tenantHasEntraP2(snapshot);

  // Map deployed policies by baseline code or name
  const policyMap = new Map<string, CAPolicyRule>();
  for (const p of deployedPolicies) {
    if (p.baselineCode) {
      policyMap.set(p.baselineCode.toUpperCase(), p);
    } else {
      const match = p.name.match(/(?:CA|CA-|\bCA\s*)(0[1-9]|10|[1-9])\b/i);
      if (match) {
        const num = parseInt(match[1], 10);
        const code = num < 10 ? `CA0${num}` : `CA${num}`;
        policyMap.set(code, p);
      }
    }
  }

  // 1. Evaluate Conditional Access Policies against Golden Template
  for (const rule of template.caPolicies) {
    evaluatedRulesCount++;
    const deployed = policyMap.get(rule.code.toUpperCase());

    // Skip P2 policies if tenant does not have P2 and policy is not deployed
    if (rule.requiresEntraP2 && !hasP2 && !deployed) {
      // Not a violation if tenant doesn't have license, but note as low severity advisory
      findings.push({
        id: `drift-ca-p2-${snapshot.tenant.id}-${rule.code}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "conditional_access",
        ruleCode: rule.code,
        ruleName: rule.name,
        severity: "low",
        expectedState: "Requires Entra ID Plan 2",
        actualState: "Not Licensed (P2 Missing)",
        driftDescription: `Policy ${rule.code} requires Entra ID Plan 2 telemetry. Tenant is currently on ${snapshot.tenant.tier.replace("_", " ")}.`,
        detectedTimestamp: new Date().toISOString(),
        remediationAction: "Upgrade tenant license or acquire Entra ID P2 add-on to enforce.",
        remediationSupported: false,
      });
      continue;
    }

    if (!deployed) {
      findings.push({
        id: `drift-ca-missing-${snapshot.tenant.id}-${rule.code}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "conditional_access",
        ruleCode: rule.code,
        ruleName: rule.name,
        severity: rule.code === "CA01" || rule.code === "CA02" || rule.code === "CA03" ? "critical" : "high",
        expectedState: rule.requiredState === "enabled" ? "On (Enabled)" : "Report-Only (or Enabled)",
        actualState: "Missing (Not Deployed)",
        driftDescription: `Baseline policy ${rule.code} (${rule.name}) is missing from tenant.`,
        detectedTimestamp: new Date().toISOString(),
        remediationAction: `Deploy baseline ${rule.code} in Report-Only mode via Golden Rollout.`,
        remediationSupported: true,
        remediationPayload: { action: "deploy_ca", baselineCode: rule.code },
      });
    } else if (deployed.state === "disabled") {
      findings.push({
        id: `drift-ca-disabled-${snapshot.tenant.id}-${rule.code}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "conditional_access",
        ruleCode: rule.code,
        ruleName: rule.name,
        severity: "critical",
        expectedState: "Report-Only or Enabled",
        actualState: "Disabled (Turned Off)",
        driftDescription: `Baseline policy ${rule.code} exists in tenant but has been disabled manually, bypassing zero-trust controls.`,
        detectedTimestamp: new Date().toISOString(),
        remediationAction: `Re-enable policy ${rule.code} in Report-Only or Enabled state.`,
        remediationSupported: true,
        remediationPayload: { action: "enable_ca", policyId: deployed.id, baselineCode: rule.code },
      });
    } else {
      // Passing
      passingRulesCount++;
    }
  }

  // 2. Evaluate External Forwarding Rule Controls
  if (template.requireExternalForwardingBlocked) {
    evaluatedRulesCount++;
    const externalRules = (snapshot.emailForwarding || []).filter(
      (r) => r.isExternal && r.state !== "Disabled"
    );

    if (externalRules.length > 0) {
      findings.push({
        id: `drift-fwd-${snapshot.tenant.id}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "mailflow",
        ruleCode: "SEC-FWD-01",
        ruleName: "Block Auto-Forwarding to External Domains",
        severity: "critical",
        expectedState: "0 External Forwarding Rules",
        actualState: `${externalRules.length} Active External Forwarding Rules`,
        driftDescription: `Detected ${externalRules.length} active mail forwarding rule(s) exfiltrating mail to external recipient domains.`,
        detectedTimestamp: new Date().toISOString(),
        remediationAction: "Disable external forwarding rules in Mail Flow Security module.",
        remediationSupported: true,
        remediationPayload: { action: "disable_forwarding_rules", ruleIds: externalRules.map((r) => r.id) },
      });
    } else {
      passingRulesCount++;
    }
  }

  // 3. Evaluate Mailbox Audit Logging
  if (template.requireMailboxAuditLogging) {
    evaluatedRulesCount++;
    const auditingDisabled = snapshot.mailboxAuditingEnabled === false;

    if (auditingDisabled) {
      findings.push({
        id: `drift-audit-mb-${snapshot.tenant.id}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "mailboxes",
        ruleCode: "SEC-MBX-AUDIT",
        ruleName: "Enforce Mailbox Audit Logging",
        severity: "high",
        expectedState: "Audit Logging Enabled (Org-Wide)",
        actualState: "Audit Logging Disabled",
        driftDescription: "Tenant-wide Exchange Online mailbox audit logging is disabled (AuditDisabled = $true), preventing forensic investigation.",
        detectedTimestamp: new Date().toISOString(),
        remediationAction: "Enable organization mailbox audit logging via Exchange Online configuration.",
        remediationSupported: true,
        remediationPayload: { action: "enable_mailbox_auditing" },
      });
    } else {
      passingRulesCount++;
    }
  }

  // 4. Evaluate DKIM / Domain Authentication
  if (template.requireDkimSigning) {
    evaluatedRulesCount++;
    const domainAuthList = snapshot.domainAuth || [];
    const missingDkimDomains = domainAuthList.filter(
      (d) => d.dkim?.status === "fail" || d.dkim?.status === "warn"
    );

    if (missingDkimDomains.length > 0) {
      findings.push({
        id: `drift-dkim-${snapshot.tenant.id}`,
        tenantId: snapshot.tenant.id,
        tenantName: snapshot.tenant.displayName,
        component: "mailflow",
        ruleCode: "SEC-DNS-DKIM",
        ruleName: "DKIM Key Signing & Verification",
        severity: "medium",
        expectedState: "DKIM Enabled & Valid on All Accepted Domains",
        actualState: `${missingDkimDomains.length} Domain(s) Missing Valid DKIM`,
        driftDescription: `Domain(s) [${missingDkimDomains.map((d) => d.domain).join(", ")}] are missing valid DKIM signing keys in Exchange Online.`,
        detectedTimestamp: new Date().toISOString(),
        remediationAction: "Generate and publish CNAME records in public DNS and enable DKIM signing.",
        remediationSupported: false,
      });
    } else {
      passingRulesCount++;
    }
  }

  // 5. Evaluate Secure Score Floor
  evaluatedRulesCount++;
  const currentScore = snapshot.secureScore?.percentage || 0;
  if (currentScore < template.minimumSecureScore) {
    findings.push({
      id: `drift-sec-score-${snapshot.tenant.id}`,
      tenantId: snapshot.tenant.id,
      tenantName: snapshot.tenant.displayName,
      component: "identity",
      ruleCode: "SEC-BENCH-SCORE",
      ruleName: "Minimum Secure Score Threshold",
      severity: "medium",
      expectedState: `>= ${template.minimumSecureScore}% Secure Score`,
      actualState: `${currentScore.toFixed(1)}% Current Score`,
      driftDescription: `Tenant Secure Score (${currentScore.toFixed(1)}%) is below the MSP Golden Baseline minimum target of ${template.minimumSecureScore}%.`,
      detectedTimestamp: new Date().toISOString(),
      remediationAction: "Review and complete prioritized improvement actions in Defender Secure Score.",
      remediationSupported: false,
    });
  } else {
    passingRulesCount++;
  }

  // Compute Alignment Score (0-100)
  const alignmentScore =
    evaluatedRulesCount > 0
      ? Math.round((passingRulesCount / evaluatedRulesCount) * 100)
      : 100;

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  const highFindings = findings.filter((f) => f.severity === "high");

  let status: "in_sync" | "minor_drift" | "critical_drift" = "in_sync";
  if (criticalFindings.length > 0 || alignmentScore < 70) {
    status = "critical_drift";
  } else if (highFindings.length > 0 || findings.length > 0) {
    status = "minor_drift";
  }

  return {
    tenantId: snapshot.tenant.id,
    tenantName: snapshot.tenant.displayName,
    defaultDomainName: snapshot.tenant.defaultDomainName,
    alignmentScore,
    status,
    totalEvaluatedRules: evaluatedRulesCount,
    passingRulesCount,
    driftedRulesCount: findings.length,
    findings,
  };
}

/**
 * Aggregates drift assessments across all managed tenant snapshots.
 */
export function evaluateFleetDrift(
  snapshots: TenantSecuritySnapshot[],
  template: GoldenBaselineTemplate = DEFAULT_GOLDEN_BASELINE
): FleetDriftSummary {
  const tenantAssessments: TenantDriftAssessment[] = [];
  const allFindings: TenantDriftFinding[] = [];

  let inSyncCount = 0;
  let minorDriftCount = 0;
  let criticalDriftCount = 0;
  let totalAlignmentSum = 0;

  for (const snap of snapshots) {
    const assessment = evaluateTenantDrift(snap, template);
    tenantAssessments.push(assessment);
    allFindings.push(...assessment.findings);

    totalAlignmentSum += assessment.alignmentScore;

    if (assessment.status === "in_sync") inSyncCount++;
    else if (assessment.status === "minor_drift") minorDriftCount++;
    else if (assessment.status === "critical_drift") criticalDriftCount++;
  }

  // Sort assessments: worst alignment (critical drift) first
  tenantAssessments.sort((a, b) => a.alignmentScore - b.alignmentScore);

  const overallFleetAlignmentPercentage =
    tenantAssessments.length > 0
      ? Math.round(totalAlignmentSum / tenantAssessments.length)
      : 100;

  return {
    totalTenantsEvaluated: tenantAssessments.length,
    inSyncCount,
    minorDriftCount,
    criticalDriftCount,
    overallFleetAlignmentPercentage,
    tenantAssessments,
    allFindings,
  };
}

/**
 * Simulates or applies an immediate realignment of a specific drift finding on a snapshot.
 */
export function realignFindingLocally(
  snapshot: TenantSecuritySnapshot,
  finding: TenantDriftFinding
): TenantSecuritySnapshot {
  const updated: TenantSecuritySnapshot = JSON.parse(JSON.stringify(snapshot));

  if (finding.remediationPayload?.action === "deploy_ca") {
    const code = finding.remediationPayload.baselineCode;
    const standardDef = CA_BASELINE_STANDARDS.find((b) => b.code === code);
    if (standardDef) {
      const existingPolicies = updated.conditionalAccess?.policies || [];
      const newPolicy: CAPolicyRule = {
        id: `pol-realign-${Date.now()}-${code.toLowerCase()}`,
        name: `${code}: ${standardDef.name}`,
        state: "enabledForReportingButNotEnforced",
        baselineCode: code,
        createdDateTime: new Date().toISOString(),
        modifiedDateTime: new Date().toISOString(),
        grantControls: ["mfa"],
        conditions: {
          users: { include: ["All"], exclude: [] },
          applications: { include: ["All"], exclude: [] },
          clientAppTypes: ["all"],
        },
        matchesBaseline: true,
      };
      updated.conditionalAccess = {
        ...updated.conditionalAccess,
        policies: [...existingPolicies, newPolicy],
      };
    }
  } else if (finding.remediationPayload?.action === "enable_ca") {
    const policyId = finding.remediationPayload.policyId;
    if (updated.conditionalAccess?.policies) {
      updated.conditionalAccess.policies = updated.conditionalAccess.policies.map((p) =>
        p.id === policyId ? { ...p, state: "enabledForReportingButNotEnforced", modifiedDateTime: new Date().toISOString() } : p
      );
    }
  } else if (finding.remediationPayload?.action === "disable_forwarding_rules") {
    const ruleIds = finding.remediationPayload.ruleIds as string[];
    if (updated.emailForwarding) {
      updated.emailForwarding = updated.emailForwarding.map((r) =>
        ruleIds.includes(r.id) ? { ...r, state: "Disabled" as const } : r
      );
    }
  } else if (finding.remediationPayload?.action === "enable_mailbox_auditing") {
    updated.mailboxAuditingEnabled = true;
  }

  return updated;
}
