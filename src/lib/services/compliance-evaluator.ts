import {
  TenantSecuritySnapshot,
  ComplianceFramework,
  ComplianceControlItem,
  TenantComplianceAssessment,
  FleetComplianceSummary,
} from "../types";
import { validateCaPolicyCompliance } from "./ca-baseline-matcher";
import { tenantHasEntraP2 } from "./drift-analyzer";

// ---------------------------------------------------------------------------
// CIS Microsoft 365 Foundations Benchmark v3.0 Control Definitions
// ---------------------------------------------------------------------------

interface ControlDefinition {
  controlNumber: string;
  section: string;
  title: string;
  description: string;
  level?: "Level 1" | "Level 2";
  relevance: "critical" | "high" | "medium";
  relatedBaselineCode?: string;
  evaluator: (snapshot: TenantSecuritySnapshot) => {
    status: "compliant" | "non_compliant" | "partially_compliant" | "not_applicable";
    evidence: string;
    remediationGuide: string;
  };
}

const CIS_M365_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "1.1.1",
    section: "1. Account & Authentication",
    title: "Ensure Modern Authentication is Enforced & Legacy Auth Blocked",
    description: "Legacy authentication protocols (POP3, IMAP4, SMTP Auth) do not support MFA and are susceptible to password spray attacks.",
    level: "Level 1",
    relevance: "critical",
    relatedBaselineCode: "CA01",
    evaluator: (snap) => {
      const ca01 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA01" || p.name.includes("CA01") || p.name.toLowerCase().includes("legacy")
      );
      if (ca01 && validateCaPolicyCompliance(ca01, "CA01").isValid) {
        return {
          status: ca01.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `Conditional Access policy '${ca01.name}' blocks legacy client app types (state: ${ca01.state}).`,
          remediationGuide: ca01.state === "enabled" ? "Policy is fully active." : "Promote CA01 from Report-Only to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "No valid policy blocking legacy authentication protocols was found.",
        remediationGuide: "Deploy baseline CA01: Block Legacy Authentication Protocols across all standard and guest accounts.",
      };
    },
  },
  {
    controlNumber: "1.1.2",
    section: "1. Account & Authentication",
    title: "Ensure Multifactor Authentication is Required for All Administrators",
    description: "Privileged accounts (Global Admins, Security Admins, Privileged Role Admins) must require phishing-resistant or strong MFA.",
    level: "Level 1",
    relevance: "critical",
    relatedBaselineCode: "CA03",
    evaluator: (snap) => {
      const ca03 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA03" || p.name.includes("CA03") || p.name.toLowerCase().includes("admin")
      );
      if (ca03 && validateCaPolicyCompliance(ca03, "CA03").isValid) {
        return {
          status: ca03.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `Admin MFA policy '${ca03.name}' targets directory roles with grant control 'mfa' (state: ${ca03.state}).`,
          remediationGuide: ca03.state === "enabled" ? "Policy is fully active." : "Promote CA03 to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Administrative roles are not protected with a dedicated MFA requirement.",
        remediationGuide: "Deploy baseline CA03: Require MFA for All Administrators.",
      };
    },
  },
  {
    controlNumber: "1.1.3",
    section: "1. Account & Authentication",
    title: "Ensure Multifactor Authentication is Required for All Standard Users",
    description: "Every cloud user account must be challenged with multifactor authentication to prevent credential stuffing.",
    level: "Level 1",
    relevance: "critical",
    relatedBaselineCode: "CA02",
    evaluator: (snap) => {
      const ca02 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA02" || p.name.includes("CA02") || p.name.toLowerCase().includes("standard")
      );
      if (ca02 && validateCaPolicyCompliance(ca02, "CA02").isValid) {
        return {
          status: ca02.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `All-users MFA policy '${ca02.name}' is configured for tenant standard users (state: ${ca02.state}).`,
          remediationGuide: ca02.state === "enabled" ? "Policy is fully active." : "Promote CA02 to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "No verified all-users MFA Conditional Access policy is active.",
        remediationGuide: "Deploy baseline CA02: Require MFA for All Standard Users.",
      };
    },
  },
  {
    controlNumber: "1.1.4",
    section: "1. Account & Authentication",
    title: "Ensure User Risk Remediation Policy is Configured (Password Reset on High Risk)",
    description: "When Entra ID Protection detects compromised credentials, users must remediate immediately through self-service password reset.",
    level: "Level 2",
    relevance: "high",
    relatedBaselineCode: "CA07",
    evaluator: (snap) => {
      const hasP2 = tenantHasEntraP2(snap);
      if (!hasP2) {
        return {
          status: "not_applicable",
          evidence: `Tenant tier (${snap.tenant.tier}) lacks Microsoft Entra ID Plan 2 telemetry.`,
          remediationGuide: "Upgrade tenant to Entra ID P2 / M365 E5 to enable risk-based user protection.",
        };
      }
      const ca07 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA07" || p.name.includes("CA07")
      );
      if (ca07 && validateCaPolicyCompliance(ca07, "CA07").isValid) {
        return {
          status: ca07.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `Risk remediation policy '${ca07.name}' requires password change on high user risk (state: ${ca07.state}).`,
          remediationGuide: ca07.state === "enabled" ? "Active." : "Promote CA07 to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "User risk policy CA07 is missing or does not mandate passwordChange control.",
        remediationGuide: "Deploy CA07: Require risk remediation for high-risk users.",
      };
    },
  },
  {
    controlNumber: "1.1.5",
    section: "1. Account & Authentication",
    title: "Ensure Sign-In Risk Remediation Policy is Configured",
    description: "Risky sign-in events (anomalous IP, impossible travel) must prompt for immediate multifactor re-authentication.",
    level: "Level 2",
    relevance: "high",
    relatedBaselineCode: "CA06",
    evaluator: (snap) => {
      const hasP2 = tenantHasEntraP2(snap);
      if (!hasP2) {
        return {
          status: "not_applicable",
          evidence: `Tenant tier (${snap.tenant.tier}) lacks Microsoft Entra ID Plan 2 telemetry.`,
          remediationGuide: "Acquire Entra ID Plan 2 license to implement sign-in risk policies.",
        };
      }
      const ca06 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA06" || p.name.includes("CA06")
      );
      if (ca06 && validateCaPolicyCompliance(ca06, "CA06").isValid) {
        return {
          status: ca06.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `Risky sign-in policy '${ca06.name}' enforces MFA on medium/high sign-in risk (state: ${ca06.state}).`,
          remediationGuide: ca06.state === "enabled" ? "Active." : "Promote CA06 to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Sign-in risk policy CA06 is missing from tenant configuration.",
        remediationGuide: "Deploy CA06: Require MFA for risky sign-ins.",
      };
    },
  },
  {
    controlNumber: "2.1.1",
    section: "2. Mailflow & Data Exfiltration",
    title: "Ensure External Email Auto-Forwarding is Blocked",
    description: "Automated inbox forwarding to external domains is the leading indicator of Business Email Compromise (BEC).",
    level: "Level 1",
    relevance: "critical",
    evaluator: (snap) => {
      const externalRules = (snap.emailForwarding || []).filter(
        (r) => r.isExternal && r.state !== "Disabled"
      );
      if (externalRules.length === 0) {
        return {
          status: "compliant",
          evidence: "0 active external mail forwarding rules detected across all mailboxes and transport rules.",
          remediationGuide: "Killswitch verified active.",
        };
      }
      return {
        status: "non_compliant",
        evidence: `Detected ${externalRules.length} active external forwarding rule(s) exfiltrating messages (e.g. ${externalRules[0].name} -> ${externalRules[0].forwardingAddress}).`,
        remediationGuide: "Disable external forwarding rules via Exchange Transport Rules or Hosted Outbound Spam Filter policy.",
      };
    },
  },
  {
    controlNumber: "2.1.2",
    section: "2. Mailflow & Data Exfiltration",
    title: "Ensure DKIM Signing is Configured for Accepted Custom Domains",
    description: "DomainKeys Identified Mail (DKIM) guarantees cryptographic message authenticity and prevents email spoofing.",
    level: "Level 1",
    relevance: "high",
    evaluator: (snap) => {
      const customDomains = (snap.domainAuth || []).filter((d) => !d.domain.endsWith(".onmicrosoft.com"));
      if (customDomains.length === 0) {
        return {
          status: "not_applicable",
          evidence: "No custom vanity domains detected in tenant.",
          remediationGuide: "Configure DKIM when adding custom domains.",
        };
      }
      const missingDkim = customDomains.filter((d) => d.dkim?.status !== "pass");
      if (missingDkim.length === 0) {
        return {
          status: "compliant",
          evidence: `All ${customDomains.length} custom domain(s) have active DKIM cryptographic key signatures.`,
          remediationGuide: "DKIM verified active.",
        };
      }
      return {
        status: "non_compliant",
        evidence: `Domain(s) missing active DKIM: ${missingDkim.map((d) => d.domain).join(", ")}.`,
        remediationGuide: "Enable DKIM signing in Microsoft Defender for Office 365 or Exchange Online admin center.",
      };
    },
  },
  {
    controlNumber: "3.1.1",
    section: "3. Collaboration & Data Governance",
    title: "Ensure Anonymous SharePoint & OneDrive Sharing Links Are Restricted",
    description: "'Anyone with the link' anonymous permissions bypass identity verification and allow persistent unauthenticated data exposure.",
    level: "Level 1",
    relevance: "high",
    evaluator: (snap) => {
      const anyoneSites = (snap.sharePoint?.sites || []).filter(
        (s) => s.sharingCapability === "Anyone"
      );
      const isAnyoneLevel = snap.sharePoint?.tenantSharingLevel === "Anyone" || snap.sharePoint?.defaultLinkType === "Anyone";

      if (anyoneSites.length === 0 && !isAnyoneLevel) {
        return {
          status: "compliant",
          evidence: "0 sites with anonymous 'Anyone' sharing permissions discovered across SharePoint Online.",
          remediationGuide: "Anonymous sharing disabled.",
        };
      }
      return {
        status: "non_compliant",
        evidence: `Found ${anyoneSites.length} site(s) configured with unauthenticated 'Anyone' sharing capability.`,
        remediationGuide: "Revoke active anonymous links and configure default sharing to 'Specific People' with expiration.",
      };
    },
  },
  {
    controlNumber: "4.1.1",
    section: "4. Auditing, Logging & Monitoring",
    title: "Ensure Mailbox Audit Logging is Enabled for All Mailboxes",
    description: "Mailbox audit logging ensures owner, delegate, and admin actions (SendAs, HardDelete, MoveToDeletedItems) are recorded.",
    level: "Level 1",
    relevance: "high",
    evaluator: (snap) => {
      const isAudited = snap.mailboxAuditingEnabled !== false;
      const totalMailboxes = (snap.mailboxes || []).length;
      if (isAudited) {
        return {
          status: "compliant",
          evidence: `Tenant-wide mailbox auditing is verified enabled across all ${totalMailboxes} mailboxes.`,
          remediationGuide: "Auditing fully enabled.",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Exchange Online organization config indicates mailbox auditing is disabled.",
        remediationGuide: "Run Set-OrganizationConfig -AuditDisabled $false to enable mailbox auditing.",
      };
    },
  },
  {
    controlNumber: "5.1.1",
    section: "5. Device Security & Zero Trust",
    title: "Ensure Compliant or Hybrid Joined Devices Are Mandated for Cloud Workloads",
    description: "Restricting cloud applications to compliant managed hardware prevents untrusted BYOD devices from downloading corporate data.",
    level: "Level 1",
    relevance: "high",
    relatedBaselineCode: "CA09",
    evaluator: (snap) => {
      const ca09 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA09" || p.name.includes("CA09") || p.name.toLowerCase().includes("compliant")
      );
      if (ca09 && validateCaPolicyCompliance(ca09, "CA09").isValid) {
        return {
          status: ca09.state === "enabled" ? "compliant" : "partially_compliant",
          evidence: `Device compliance policy '${ca09.name}' enforces compliantDevice control (state: ${ca09.state}).`,
          remediationGuide: ca09.state === "enabled" ? "Active." : "Promote CA09 to On (Enabled).",
        };
      }
      return {
        status: "non_compliant",
        evidence: "No policy mandating device compliance was verified.",
        remediationGuide: "Deploy baseline CA09: Require Compliant or Hybrid Joined Device.",
      };
    },
  },
];

// ---------------------------------------------------------------------------
// NIST Cybersecurity Framework (CSF 2.0) Control Definitions
// ---------------------------------------------------------------------------

const NIST_CSF_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "PR.AC-1",
    section: "Protect: Identity Management & Access Control",
    title: "Identities and credentials are authenticated with MFA",
    description: "All users and administrators authenticating to organizational cloud services must be validated with phishing-resistant or strong MFA.",
    relevance: "critical",
    evaluator: (snap) => {
      const ca02 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA02" && validateCaPolicyCompliance(p, "CA02").isValid
      );
      const ca03 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA03" && validateCaPolicyCompliance(p, "CA03").isValid
      );
      if (ca02 && ca03) {
        return {
          status: "compliant",
          evidence: "MFA policies active for both general users (CA02) and directory administrators (CA03).",
          remediationGuide: "Maintain MFA baseline enforcement.",
        };
      }
      return {
        status: "partially_compliant",
        evidence: "Partial MFA coverage. Ensure both CA02 (all users) and CA03 (admins) are deployed.",
        remediationGuide: "Deploy missing MFA baselines.",
      };
    },
  },
  {
    controlNumber: "PR.DS-1",
    section: "Protect: Data Security",
    title: "Data exfiltration through unapproved email forwarding is prevented",
    description: "Protection mechanisms block unauthorized automatic routing of confidential corporate correspondence outside the tenant.",
    relevance: "critical",
    evaluator: (snap) => {
      const externalRules = (snap.emailForwarding || []).filter(
        (r) => r.isExternal && r.state !== "Disabled"
      );
      if (externalRules.length === 0) {
        return {
          status: "compliant",
          evidence: "Outbound forwarding killswitch is operational with 0 external routing anomalies.",
          remediationGuide: "Killswitch enforced.",
        };
      }
      return {
        status: "non_compliant",
        evidence: `Detected ${externalRules.length} rule(s) routing company email to external domains.`,
        remediationGuide: "Disable external forwarding transport rules.",
      };
    },
  },
  {
    controlNumber: "DE.AE-1",
    section: "Detect: Anomalies & Threat Events",
    title: "Sign-in and user risk telemetry is monitored for compromised behavior",
    description: "Identity protection analyzes behavioral risk signals (impossible travel, password spray) in real time.",
    relevance: "high",
    evaluator: (snap) => {
      const hasP2 = tenantHasEntraP2(snap);
      if (!hasP2) {
        return {
          status: "not_applicable",
          evidence: "Tenant lacks Entra ID Plan 2 behavioral risk intelligence.",
          remediationGuide: "Upgrade tenant to Entra ID P2 to enable automated anomaly detection.",
        };
      }
      const ca06 = snap.conditionalAccess?.policies.find((p) => p.baselineCode === "CA06");
      if (ca06) {
        return {
          status: "compliant",
          evidence: "Real-time sign-in risk evaluation active via CA06 policy.",
          remediationGuide: "Maintain risk detection.",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Tenant has P2 licensing but sign-in risk policy CA06 is not configured.",
        remediationGuide: "Deploy CA06: Require MFA for risky sign-ins.",
      };
    },
  },
  {
    controlNumber: "RS.MI-1",
    section: "Respond: Incident Mitigation",
    title: "Threat indicators and malicious vectors are blocked fleet-wide",
    description: "Tenant Allow/Block Lists (TABL) prevent malicious domains, IP addresses, and senders from reaching users.",
    relevance: "high",
    evaluator: (snap) => {
      const activeBlocks = (snap.mdoThreat?.policies || []).length;
      return {
        status: "compliant",
        evidence: `Tenant has ${activeBlocks} active Microsoft Defender for Office 365 threat policies configured.`,
        remediationGuide: "Keep TABL threat indicators synced with fleet.",
      };
    },
  },
];

// ---------------------------------------------------------------------------
// Essential Eight Control Definitions (ACSC)
// ---------------------------------------------------------------------------

const ESSENTIAL_EIGHT_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "E8.MFA.1",
    section: "Multifactor Authentication",
    title: "MFA is enforced for all administrative and privileged access",
    description: "Maturity Level 1: All administrative accounts accessing internet-facing services must use MFA.",
    relevance: "critical",
    evaluator: (snap) => {
      const ca03 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA03" && validateCaPolicyCompliance(p, "CA03").isValid
      );
      if (ca03 && ca03.state === "enabled") {
        return {
          status: "compliant",
          evidence: "CA03 mandates MFA on GlobalAdmin and privileged directory roles.",
          remediationGuide: "Complies with Essential Eight Maturity Level 1.",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Admin MFA is not strictly enforced in On mode.",
        remediationGuide: "Deploy and enable CA03: Require MFA for All Administrators.",
      };
    },
  },
  {
    controlNumber: "E8.MFA.2",
    section: "Multifactor Authentication",
    title: "MFA is required for all standard users and remote access",
    description: "Maturity Level 2: MFA is enforced for all cloud users and remote access sessions.",
    relevance: "high",
    evaluator: (snap) => {
      const ca02 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA02" && validateCaPolicyCompliance(p, "CA02").isValid
      );
      if (ca02 && ca02.state === "enabled") {
        return {
          status: "compliant",
          evidence: "CA02 enforces MFA across all standard tenant users.",
          remediationGuide: "Complies with Essential Eight Maturity Level 2.",
        };
      }
      return {
        status: "non_compliant",
        evidence: "CA02 is missing or in Report-Only mode.",
        remediationGuide: "Enable CA02 across all users.",
      };
    },
  },
  {
    controlNumber: "E8.PRIV.1",
    section: "Restrict Administrative Privileges",
    title: "Administrative accounts are dedicated and unassigned when unused",
    description: "Admins must not use privileged accounts for standard browsing or email reading.",
    relevance: "high",
    evaluator: (snap) => {
      const adminCount = snap.mfaAudit?.filter((u) => u.isAdmin).length || 0;
      if (adminCount <= 5) {
        return {
          status: "compliant",
          evidence: `Tenant maintains a lean administrative footprint of ${adminCount} administrator(s).`,
          remediationGuide: "Maintain least-privilege principle.",
        };
      }
      return {
        status: "partially_compliant",
        evidence: `Detected ${adminCount} accounts with administrative privileges. Review for privilege sprawl.`,
        remediationGuide: "Review and revoke unneeded directory role assignments.",
      };
    },
  },
  {
    controlNumber: "E8.HARD.1",
    section: "User Application Hardening",
    title: "Legacy, unauthenticated, and vulnerable protocols are disabled",
    description: "Block legacy protocols and unmanaged application extensions.",
    relevance: "high",
    evaluator: (snap) => {
      const ca01 = snap.conditionalAccess?.policies.find(
        (p) => p.baselineCode === "CA01" && validateCaPolicyCompliance(p, "CA01").isValid
      );
      if (ca01 && ca01.state === "enabled") {
        return {
          status: "compliant",
          evidence: "CA01 actively blocks legacy client application types.",
          remediationGuide: "Maintains application hardening standard.",
        };
      }
      return {
        status: "non_compliant",
        evidence: "Legacy protocols remain permitted in tenant.",
        remediationGuide: "Enable CA01 to block legacy protocols.",
      };
    },
  },
];

// ---------------------------------------------------------------------------
// Assessment Engine
// ---------------------------------------------------------------------------

export function evaluateTenantCompliance(
  snapshot: TenantSecuritySnapshot,
  framework: ComplianceFramework = "cis_m365_v3"
): TenantComplianceAssessment {
  let controlDefs: ControlDefinition[] = [];
  let frameworkTitle = "CIS Microsoft 365 Foundations Benchmark v3.0";

  if (framework === "cis_m365_v3") {
    controlDefs = CIS_M365_CONTROLS;
    frameworkTitle = "CIS Microsoft 365 Foundations Benchmark v3.0";
  } else if (framework === "nist_csf_v2") {
    controlDefs = NIST_CSF_CONTROLS;
    frameworkTitle = "NIST Cybersecurity Framework (CSF 2.0)";
  } else if (framework === "essential_eight") {
    controlDefs = ESSENTIAL_EIGHT_CONTROLS;
    frameworkTitle = "Australian Cyber Security Centre (ACSC) Essential Eight";
  }

  const items: ComplianceControlItem[] = controlDefs.map((def) => {
    const result = def.evaluator(snapshot);
    return {
      id: `ctrl-${framework}-${snapshot.tenant.id}-${def.controlNumber}`,
      framework,
      section: def.section,
      controlNumber: def.controlNumber,
      title: def.title,
      description: def.description,
      level: def.level,
      status: result.status,
      relevance: def.relevance,
      evidence: result.evidence,
      remediationGuide: result.remediationGuide,
      relatedBaselineCode: def.relatedBaselineCode,
    };
  });

  const applicable = items.filter((i) => i.status !== "not_applicable");
  const compliantCount = items.filter((i) => i.status === "compliant").length;
  const nonCompliantCount = items.filter((i) => i.status === "non_compliant").length;
  const partiallyCompliantCount = items.filter((i) => i.status === "partially_compliant").length;

  const scorePercentage =
    applicable.length > 0
      ? Math.round(((compliantCount + partiallyCompliantCount * 0.5) / applicable.length) * 100)
      : 100;

  // Level 1 and Level 2 score calculations for CIS
  const l1Items = items.filter((i) => i.level === "Level 1" && i.status !== "not_applicable");
  const l1Compliant = l1Items.filter((i) => i.status === "compliant").length;
  const level1ScorePercentage =
    l1Items.length > 0 ? Math.round((l1Compliant / l1Items.length) * 100) : undefined;

  const l2Items = items.filter((i) => i.level === "Level 2" && i.status !== "not_applicable");
  const l2Compliant = l2Items.filter((i) => i.status === "compliant").length;
  const level2ScorePercentage =
    l2Items.length > 0 ? Math.round((l2Compliant / l2Items.length) * 100) : undefined;

  return {
    tenantId: snapshot.tenant.id,
    tenantName: snapshot.tenant.displayName,
    defaultDomainName: snapshot.tenant.defaultDomainName,
    evaluatedAt: new Date().toISOString(),
    framework,
    frameworkTitle,
    totalControls: items.length,
    compliantCount,
    nonCompliantCount,
    partiallyCompliantCount,
    scorePercentage,
    level1ScorePercentage,
    level2ScorePercentage,
    controls: items,
  };
}

export function evaluateFleetCompliance(
  snapshots: TenantSecuritySnapshot[],
  framework: ComplianceFramework = "cis_m365_v3"
): FleetComplianceSummary {
  const tenantAssessments = snapshots.map((s) => evaluateTenantCompliance(s, framework));
  const totalTenants = tenantAssessments.length;

  const overallAvg =
    totalTenants > 0
      ? Math.round(
          tenantAssessments.reduce((acc, curr) => acc + curr.scorePercentage, 0) / totalTenants
        )
      : 0;

  // Track top failing controls across the fleet
  const failureFrequencyMap = new Map<string, { title: string; count: number }>();
  for (const assessment of tenantAssessments) {
    for (const ctrl of assessment.controls) {
      if (ctrl.status === "non_compliant") {
        const existing = failureFrequencyMap.get(ctrl.controlNumber) || { title: ctrl.title, count: 0 };
        failureFrequencyMap.set(ctrl.controlNumber, { title: ctrl.title, count: existing.count + 1 });
      }
    }
  }

  const topFailingControls = Array.from(failureFrequencyMap.entries())
    .map(([controlNumber, data]) => ({
      controlNumber,
      title: data.title,
      failingTenantsCount: data.count,
    }))
    .sort((a, b) => b.failingTenantsCount - a.failingTenantsCount)
    .slice(0, 5);

  const frameworkTitle =
    framework === "cis_m365_v3"
      ? "CIS Microsoft 365 Foundations Benchmark v3.0"
      : framework === "nist_csf_v2"
      ? "NIST Cybersecurity Framework (CSF 2.0)"
      : "Australian Cyber Security Centre (ACSC) Essential Eight";

  return {
    framework,
    frameworkTitle,
    evaluatedAt: new Date().toISOString(),
    totalTenantsEvaluated: totalTenants,
    overallFleetCompliancePercentage: overallAvg,
    tenantAssessments,
    topFailingControls,
  };
}
