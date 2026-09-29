import {
  TenantSecuritySnapshot,
  ComplianceFramework,
  ComplianceControlItem,
  TenantComplianceAssessment,
  FleetComplianceSummary,
} from "../types";
import { validateCaPolicyCompliance } from "./ca-baseline-matcher";
import { tenantHasEntraP2 } from "./drift-analyzer";
import { DATA_PROTECTION_RECOMMENDATIONS, Regulation } from "../data/data-protection-recommendations";
import { getTierEligibility } from "../utils/data-protection-tier-gating";

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
  // Present only on POPIA/GDPR/HIPAA's organizational/legal controls - see
  // ComplianceControlItem.attestationKey. When set, this control's evaluator
  // below reads snapshot.tenant.complianceAttestations[attestationKey]
  // instead of computing anything from live snapshot data.
  attestationKey?: string;
  sourceUrl?: string;
  evaluator: (snapshot: TenantSecuritySnapshot) => {
    status: "compliant" | "non_compliant" | "partially_compliant" | "not_applicable";
    evidence: string;
    remediationGuide: string;
  };
}

// Shared by every manual/attestation control below (POPIA/GDPR/HIPAA's
// organizational half) - reads the tenant's own attestation state rather
// than computing anything, and never defaults an unattested item to
// "compliant." A human must explicitly attest; absence of a record is a gap,
// not a pass.
function evaluateAttestation(
  snap: TenantSecuritySnapshot,
  key: string,
  compliantEvidence: string,
  nonCompliantRemediation: string
) {
  const record = snap.tenant.complianceAttestations?.[key];
  if (record?.attested) {
    return {
      status: "compliant" as const,
      evidence: `Attested by ${record.attestedBy || "an operator"} on ${
        record.attestedAt ? new Date(record.attestedAt).toLocaleDateString() : "an unrecorded date"
      }.${record.note ? ` Note: ${record.note}` : ""} ${compliantEvidence}`,
      remediationGuide: "Attested - no action needed unless circumstances have changed since the attestation date.",
    };
  }
  return {
    status: "non_compliant" as const,
    evidence: "Not yet attested - this is an organizational/legal requirement Clarity365 cannot verify automatically; a human must confirm it.",
    remediationGuide: nonCompliantRemediation,
  };
}

// Shared by POPIA/GDPR/HIPAA's "DLP recommendations available" auto control.
// Deliberately caps at "partially_compliant" even when every tagged
// recommendation is licence-eligible - eligibility is not the same as
// deployment, and this app has no live Purview sync to confirm a
// recommendation was actually adopted (see the DLP & Sensitivity Labels
// Plan's Stage 0/1 status). Claiming "compliant" here would overstate what's
// actually known.
function evaluateDlpEligibility(snap: TenantSecuritySnapshot, regulation: Regulation) {
  // Deliberately excludes sensitivity-label entries (added 2026-09-22) so
  // this control's own name/wording ("DLP recommendations") keeps meaning
  // what it already said before labels shared the same catalog array - a
  // silent scope change here would be exactly the kind of thing this
  // codebase's own recurring-bug-class notes warn about. The QBR's separate
  // dataProtectionSection deliberately does the opposite (counts both) since
  // its own heading already promises "DLP & Sensitivity Labels."
  const tagged = DATA_PROTECTION_RECOMMENDATIONS.filter(
    (r) => r.regulations.includes(regulation) && !("kind" in r && r.kind === "label")
  );
  const eligible = tagged.filter((r) => getTierEligibility(snap.tenant.tier, r.minimumLicenseTier) === "eligible");

  if (eligible.length === 0) {
    return {
      status: "non_compliant" as const,
      evidence: `0 of ${tagged.length} ${regulation}-tagged DLP recommendations are available on this tenant's licence (${snap.tenant.tier}).`,
      remediationGuide: "Review the Data Protection module's licence requirements - an upgrade may be needed before any recommendation in this set can be deployed.",
    };
  }
  return {
    status: "partially_compliant" as const,
    evidence: `${eligible.length} of ${tagged.length} ${regulation}-tagged DLP recommendations are licence-eligible. Eligibility is not deployment - this does not confirm any of them are actually configured in Purview.`,
    remediationGuide: `Review and deploy the relevant recommendations in the Data Protection module: ${eligible.map((r) => r.title).join("; ")}.`,
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
// POPIA / GDPR / UK GDPR / HIPAA Readiness Controls (added 2026-09-22)
// ---------------------------------------------------------------------------
// Hybrid, unlike the three frameworks above: section "1." is auto-computed
// from this snapshot (mirrors CIS/NIST/Essential Eight exactly - same
// evaluator shape, same data sources); section "2." is manual attestation
// via evaluateAttestation() - organizational/legal requirements no security
// tool can verify. Every citation below was checked against a public source
// during planning, not asserted from memory - see sourceUrl on each control
// and ai-context-vault/Optimization/Compliance Readiness Checklist Plan.md
// for the full research trail. Technical-to-legal mapping for engineering
// purposes, not legal advice - confirm with the client's own legal/compliance
// counsel before presenting any of this as authoritative.

function mfaEnforcedPercent(snap: TenantSecuritySnapshot): number {
  const users = snap.mfaAudit || [];
  if (users.length === 0) return 0;
  const enforced = users.filter((u: any) => u.mfaRegistered || u.mfaEnforcedByPolicy || u.enforced).length;
  return Math.round((enforced / users.length) * 100);
}

const POPIA_READINESS_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "1.1",
    section: "1. Technical Safeguards",
    title: "Access control baseline (Conditional Access)",
    description: "POPIA s.19 requires appropriate technical measures to prevent unlawful access - Conditional Access baseline coverage is this tenant's primary access-control signal.",
    relevance: "critical",
    sourceUrl: "https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/",
    evaluator: (snap) => {
      const score = snap.conditionalAccess?.baselineCoverageScore ?? 0;
      if (score >= 80) return { status: "compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Maintain coverage; review CA Policy Baseline periodically." };
      if (score > 0) return { status: "partially_compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Deploy the remaining CA baseline policies in the CA Policy Baseline module." };
      return { status: "non_compliant", evidence: "No CA baseline policies detected.", remediationGuide: "Deploy the CA baseline (CA01-CA10) via the CA Policy Baseline module." };
    },
  },
  {
    controlNumber: "1.2",
    section: "1. Technical Safeguards",
    title: "Multi-factor authentication enforcement",
    description: "POPIA s.19's security-safeguards requirement, applied to credential compromise specifically.",
    relevance: "critical",
    sourceUrl: "https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/",
    evaluator: (snap) => {
      const pct = mfaEnforcedPercent(snap);
      if (pct >= 90) return { status: "compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Maintain coverage." };
      if (pct > 0) return { status: "partially_compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Close remaining gaps via the MFA & Auth Methods module." };
      return { status: "non_compliant", evidence: "No MFA enforcement detected.", remediationGuide: "Enforce MFA - see the MFA & Auth Methods module." };
    },
  },
  {
    controlNumber: "1.3",
    section: "1. Technical Safeguards",
    title: "Mailbox audit logging enabled",
    description: "POPIA s.17's openness/accountability principle depends on being able to investigate what happened to data after the fact.",
    relevance: "high",
    sourceUrl: "https://popia.co.za/",
    evaluator: (snap) => {
      if (snap.mailboxAuditingEnabled === undefined) return { status: "not_applicable", evidence: "Exchange Online not connected - auditing status unknown.", remediationGuide: "Connect Exchange Online to evaluate this control." };
      if (snap.mailboxAuditingEnabled) return { status: "compliant", evidence: "Tenant-wide mailbox auditing is enabled.", remediationGuide: "Maintain." };
      return { status: "non_compliant", evidence: "Mailbox auditing is disabled tenant-wide.", remediationGuide: "Run Set-OrganizationConfig -AuditDisabled $false." };
    },
  },
  {
    controlNumber: "1.4",
    section: "1. Technical Safeguards",
    title: "DLP recommendations available for identity, health & financial data",
    description: "Eligibility for this catalog's POPIA-tagged DLP/label recommendations (see the Data Protection module) - not confirmation any are deployed.",
    relevance: "high",
    evaluator: (snap) => evaluateDlpEligibility(snap, "popia"),
  },
  {
    controlNumber: "2.1",
    section: "2. Organizational & Legal",
    title: "Information Officer registered with the Information Regulator",
    description: "POPIA s.55(2) requires every Information Officer to be registered with the Information Regulator before taking up duties.",
    relevance: "critical",
    attestationKey: "popia-information-officer-registered",
    sourceUrl: "https://eservices.inforegulator.org.za/",
    evaluator: (snap) => evaluateAttestation(
      snap,
      "popia-information-officer-registered",
      "",
      "Register the Information Officer (and any Deputy) at eservices.inforegulator.org.za - free, roughly 30 minutes - then mark this attested with the date."
    ),
  },
  {
    controlNumber: "2.2",
    section: "2. Organizational & Legal",
    title: "Written operator agreements with all third-party processors",
    description: "POPIA ss.20-21 require a written contract with every operator (payroll, IT vendor, cloud provider, etc.). Without one, the client remains accountable for the operator's own non-compliance.",
    relevance: "critical",
    attestationKey: "popia-operator-agreements",
    sourceUrl: "https://popia.co.za/section-21-security-measures-regarding-information-processed-by-operator/",
    evaluator: (snap) => evaluateAttestation(
      snap,
      "popia-operator-agreements",
      "",
      "Confirm a written agreement exists with every third party processing personal information on this client's behalf, covering s.19 safeguards and breach notification."
    ),
  },
  {
    controlNumber: "2.3",
    section: "2. Organizational & Legal",
    title: "PAIA manual published",
    description: "The Promotion of Access to Information Act manual documents how the organization handles access requests - a standard companion requirement alongside POPIA.",
    relevance: "medium",
    attestationKey: "popia-paia-manual",
    evaluator: (snap) => evaluateAttestation(snap, "popia-paia-manual", "", "Publish a PAIA manual - templates are available from the Information Regulator."),
  },
  {
    controlNumber: "2.4",
    section: "2. Organizational & Legal",
    title: "Data subject access/correction request process documented",
    description: "POPIA ss.23-25 give data subjects the right to request access to, and correction of, their personal information.",
    relevance: "high",
    attestationKey: "popia-data-subject-requests",
    evaluator: (snap) => evaluateAttestation(snap, "popia-data-subject-requests", "", "Document who handles a data subject access/correction request and how, within a reasonable time."),
  },
  {
    controlNumber: "2.5",
    section: "2. Organizational & Legal",
    title: "Breach notification procedure reaches the Information Regulator",
    description: "POPIA s.22 requires notifying the Regulator (and affected data subjects) as soon as reasonably possible after a security compromise - not just an internal alert.",
    relevance: "critical",
    attestationKey: "popia-breach-notification-procedure",
    evaluator: (snap) => evaluateAttestation(snap, "popia-breach-notification-procedure", "", "Document the actual notification path to the Information Regulator, distinct from Clarity365's own internal incident reports."),
  },
  {
    controlNumber: "2.6",
    section: "2. Organizational & Legal",
    title: "Direct marketing consent mechanism (opt-in), if applicable",
    description: "POPIA s.69 requires prior opt-in consent for unsolicited electronic direct marketing.",
    relevance: "medium",
    attestationKey: "popia-direct-marketing-consent",
    evaluator: (snap) => evaluateAttestation(snap, "popia-direct-marketing-consent", "", "Confirm an opt-in consent mechanism exists before any direct marketing communication, or mark not applicable if this client does no direct marketing."),
  },
];

const GDPR_READINESS_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "1.1",
    section: "1. Technical Safeguards",
    title: "Access control baseline (Conditional Access)",
    description: "GDPR Art. 32 requires appropriate technical measures - Conditional Access baseline coverage is this tenant's primary signal.",
    relevance: "critical",
    sourceUrl: "https://gdpr-info.eu/art-32-gdpr/",
    evaluator: (snap) => {
      const score = snap.conditionalAccess?.baselineCoverageScore ?? 0;
      if (score >= 80) return { status: "compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Maintain coverage." };
      if (score > 0) return { status: "partially_compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Deploy the remaining CA baseline policies." };
      return { status: "non_compliant", evidence: "No CA baseline policies detected.", remediationGuide: "Deploy the CA baseline via the CA Policy Baseline module." };
    },
  },
  {
    controlNumber: "1.2",
    section: "1. Technical Safeguards",
    title: "Multi-factor authentication enforcement",
    description: "GDPR Art. 32(1)(b) - ongoing confidentiality of processing systems.",
    relevance: "critical",
    sourceUrl: "https://gdpr-info.eu/art-32-gdpr/",
    evaluator: (snap) => {
      const pct = mfaEnforcedPercent(snap);
      if (pct >= 90) return { status: "compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Maintain coverage." };
      if (pct > 0) return { status: "partially_compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Close remaining gaps via the MFA & Auth Methods module." };
      return { status: "non_compliant", evidence: "No MFA enforcement detected.", remediationGuide: "Enforce MFA." };
    },
  },
  {
    controlNumber: "1.3",
    section: "1. Technical Safeguards",
    title: "Mailbox audit logging enabled",
    description: "Supports Art. 30's recordkeeping and Art. 33's breach-investigation obligations.",
    relevance: "high",
    evaluator: (snap) => {
      if (snap.mailboxAuditingEnabled === undefined) return { status: "not_applicable", evidence: "Exchange Online not connected.", remediationGuide: "Connect Exchange Online to evaluate this control." };
      if (snap.mailboxAuditingEnabled) return { status: "compliant", evidence: "Tenant-wide mailbox auditing is enabled.", remediationGuide: "Maintain." };
      return { status: "non_compliant", evidence: "Mailbox auditing is disabled tenant-wide.", remediationGuide: "Run Set-OrganizationConfig -AuditDisabled $false." };
    },
  },
  {
    controlNumber: "1.4",
    section: "1. Technical Safeguards",
    title: "DLP recommendations available for identifiers & special category data",
    description: "Eligibility for this catalog's GDPR/UK GDPR-tagged DLP/label recommendations - not confirmation any are deployed.",
    relevance: "high",
    evaluator: (snap) => evaluateDlpEligibility(snap, "gdpr_uk_gdpr"),
  },
  {
    controlNumber: "2.1",
    section: "2. Organizational & Legal",
    title: "Records of Processing Activities documented (Art. 30)",
    description: "The under-250-employee exemption is real but narrow in practice - it requires non-regular processing, no special-category data, and no risk to data subjects, all at once. Ordinary payroll/HR processing alone usually disqualifies it, regardless of headcount.",
    relevance: "critical",
    attestationKey: "gdpr-ropa-documented",
    sourceUrl: "https://gdpr-info.eu/art-30-gdpr/",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-ropa-documented", "", "Document a Record of Processing Activities - don't assume the small-business exemption applies without checking all three conditions."),
  },
  {
    controlNumber: "2.2",
    section: "2. Organizational & Legal",
    title: "DPO appointed, or a documented reason why not required (Art. 37)",
    description: "Mandatory only for public authorities, large-scale systematic monitoring, or large-scale special-category/criminal-data processing as a core activity. Most SME clients won't need one - document that conclusion rather than leaving it unaddressed.",
    relevance: "medium",
    attestationKey: "gdpr-dpo-assessed",
    sourceUrl: "https://gdpr-info.eu/art-37-gdpr/",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-dpo-assessed", "", "Assess against the three Art. 37 triggers and document the conclusion, even if the answer is 'not required.'"),
  },
  {
    controlNumber: "2.3",
    section: "2. Organizational & Legal",
    title: "Data Processing Agreements in place with all processors (Art. 28)",
    description: "Every vendor processing personal data on the client's behalf needs a DPA - commonly missed for smaller/niche vendors.",
    relevance: "critical",
    attestationKey: "gdpr-dpas-in-place",
    sourceUrl: "https://gdpr-info.eu/art-28-gdpr/",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-dpas-in-place", "", "Confirm a DPA exists with every processor, not just the largest/most obvious ones."),
  },
  {
    controlNumber: "2.4",
    section: "2. Organizational & Legal",
    title: "Data subject rights process documented (Art. 12-22)",
    description: "Access, rectification, erasure, portability and objection all need a real, documented fulfillment process.",
    relevance: "high",
    attestationKey: "gdpr-data-subject-rights-process",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-data-subject-rights-process", "", "Document who handles a data subject rights request and the fulfillment timeline."),
  },
  {
    controlNumber: "2.5",
    section: "2. Organizational & Legal",
    title: "Privacy notice published (Art. 13-14)",
    description: "Data subjects must be told what's collected and why, at the point of collection.",
    relevance: "medium",
    attestationKey: "gdpr-privacy-notice-published",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-privacy-notice-published", "", "Publish a privacy notice covering the categories in Art. 13-14."),
  },
  {
    controlNumber: "2.6",
    section: "2. Organizational & Legal",
    title: "International transfer legal basis documented (Art. 44-49)",
    description: "The Data Protection module's cross-border-transfer DLP control is a technical approximation; the actual legal basis (SCCs, an adequacy decision, etc.) is a separate, required document.",
    relevance: "high",
    attestationKey: "gdpr-international-transfer-basis",
    evaluator: (snap) => evaluateAttestation(snap, "gdpr-international-transfer-basis", "", "Document the legal transfer mechanism for any personal data leaving the EU/UK."),
  },
];

const HIPAA_READINESS_CONTROLS: ControlDefinition[] = [
  {
    controlNumber: "1.1",
    section: "1. Technical Safeguards",
    title: "Access control baseline (Conditional Access)",
    description: "HIPAA 45 CFR 164.312(a) - access control technical safeguard.",
    relevance: "critical",
    sourceUrl: "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
    evaluator: (snap) => {
      const score = snap.conditionalAccess?.baselineCoverageScore ?? 0;
      if (score >= 80) return { status: "compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Maintain coverage." };
      if (score > 0) return { status: "partially_compliant", evidence: `CA baseline coverage is ${score}%.`, remediationGuide: "Deploy the remaining CA baseline policies." };
      return { status: "non_compliant", evidence: "No CA baseline policies detected.", remediationGuide: "Deploy the CA baseline via the CA Policy Baseline module." };
    },
  },
  {
    controlNumber: "1.2",
    section: "1. Technical Safeguards",
    title: "Multi-factor authentication enforcement",
    description: "HIPAA 164.312(d) - person or entity authentication (addressable - see 2.6 for what that means in practice).",
    relevance: "critical",
    evaluator: (snap) => {
      const pct = mfaEnforcedPercent(snap);
      if (pct >= 90) return { status: "compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Maintain coverage." };
      if (pct > 0) return { status: "partially_compliant", evidence: `MFA enforced for ${pct}% of audited users.`, remediationGuide: "Close remaining gaps via the MFA & Auth Methods module." };
      return { status: "non_compliant", evidence: "No MFA enforcement detected.", remediationGuide: "Enforce MFA." };
    },
  },
  {
    controlNumber: "1.3",
    section: "1. Technical Safeguards",
    title: "Audit controls (mailbox audit logging)",
    description: "HIPAA 164.312(b) - audit controls, a required (not addressable) specification.",
    relevance: "high",
    evaluator: (snap) => {
      if (snap.mailboxAuditingEnabled === undefined) return { status: "not_applicable", evidence: "Exchange Online not connected.", remediationGuide: "Connect Exchange Online to evaluate this control." };
      if (snap.mailboxAuditingEnabled) return { status: "compliant", evidence: "Tenant-wide mailbox auditing is enabled.", remediationGuide: "Maintain." };
      return { status: "non_compliant", evidence: "Mailbox auditing is disabled tenant-wide.", remediationGuide: "Run Set-OrganizationConfig -AuditDisabled $false." };
    },
  },
  {
    controlNumber: "1.4",
    section: "1. Technical Safeguards",
    title: "DLP recommendations available for PHI",
    description: "Eligibility for this catalog's HIPAA-tagged PHI DLP recommendation - not confirmation it's deployed.",
    relevance: "high",
    evaluator: (snap) => evaluateDlpEligibility(snap, "hipaa"),
  },
  {
    controlNumber: "2.1",
    section: "2. Organizational & Legal",
    title: "BAA/DPA downloaded and retained for records",
    description: "Microsoft's HIPAA BAA terms are included by default in the Products and Services Data Protection Addendum for eligible customers - not a separate document the client signs. The action is downloading and filing a copy, not chasing a signature.",
    relevance: "critical",
    attestationKey: "hipaa-baa-retained",
    sourceUrl: "https://learn.microsoft.com/en-us/answers/questions/5811334/how-to-sign-a-business-associate-agreement-and-add",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-baa-retained", "", "Download the BAA/DPA from the Microsoft Service Trust Portal and file it in the client's compliance records."),
  },
  {
    controlNumber: "2.2",
    section: "2. Organizational & Legal",
    title: "Privacy Officer and Security Officer designated",
    description: "HIPAA §164.530(a) and §164.308(a)(2) require named, responsible individuals.",
    relevance: "critical",
    attestationKey: "hipaa-officers-designated",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-officers-designated", "", "Name a Privacy Officer and a Security Officer (can be the same person in a small organization) and document it."),
  },
  {
    controlNumber: "2.3",
    section: "2. Organizational & Legal",
    title: "Documented risk analysis on file",
    description: "HIPAA §164.308(a)(1) - a required specification, the foundation the rest of the Security Rule builds on.",
    relevance: "critical",
    attestationKey: "hipaa-risk-analysis",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-risk-analysis", "", "Conduct and document a risk analysis covering all ePHI the client handles."),
  },
  {
    controlNumber: "2.4",
    section: "2. Organizational & Legal",
    title: "Workforce training completed",
    description: "HIPAA §164.308(a)(5).",
    relevance: "medium",
    attestationKey: "hipaa-workforce-training",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-workforce-training", "", "Deliver and document HIPAA workforce training."),
  },
  {
    controlNumber: "2.5",
    section: "2. Organizational & Legal",
    title: "Contingency/backup plan documented",
    description: "HIPAA §164.308(a)(7) - a required specification covering data backup, disaster recovery, and emergency operation.",
    relevance: "high",
    attestationKey: "hipaa-contingency-plan",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-contingency-plan", "", "Document a backup, disaster-recovery, and emergency-operations plan."),
  },
  {
    controlNumber: "2.6",
    section: "2. Organizational & Legal",
    title: "Notice of Privacy Practices published",
    description: "HIPAA §164.520.",
    relevance: "medium",
    attestationKey: "hipaa-npp-published",
    evaluator: (snap) => evaluateAttestation(snap, "hipaa-npp-published", "", "Publish a Notice of Privacy Practices."),
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
  } else if (framework === "popia") {
    controlDefs = POPIA_READINESS_CONTROLS;
    frameworkTitle = "POPIA Compliance Readiness";
  } else if (framework === "gdpr_uk_gdpr") {
    controlDefs = GDPR_READINESS_CONTROLS;
    frameworkTitle = "GDPR / UK GDPR Compliance Readiness";
  } else if (framework === "hipaa") {
    controlDefs = HIPAA_READINESS_CONTROLS;
    frameworkTitle = "HIPAA Compliance Readiness";
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
      attestationKey: def.attestationKey,
      sourceUrl: def.sourceUrl,
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
      : framework === "essential_eight"
      ? "Australian Cyber Security Centre (ACSC) Essential Eight"
      : framework === "popia"
      ? "POPIA Compliance Readiness"
      : framework === "gdpr_uk_gdpr"
      ? "GDPR / UK GDPR Compliance Readiness"
      : "HIPAA Compliance Readiness";

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
