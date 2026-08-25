import { MdoBaselineItem, MdoThreatPolicy } from "../types";

// Mirrors baseline-definitions.ts's CA01-CA10 pattern for Defender for
// Office 365: instead of scoring "is a policy configured," each check scores
// one specific setting against Microsoft's Standard preset security policy
// recommendation. Unlike CA (which has to infer which baseline a policy
// matches from its structure), MDO doesn't need that — policyType already
// tells you exactly which cmdlet a row came from — so evaluation in
// mdo-baseline-matcher.ts is a direct field lookup per check, not a cascade.

export interface MdoRemediationAction {
  cmdlet: string;
  buildParameters: (policy: MdoThreatPolicy) => Record<string, any>;
  summary: string;
}

export interface MdoBaselinePolicyDefinition extends MdoBaselineItem {
  remediation?: MdoRemediationAction;
}

export const MDO_BASELINE_STANDARDS: MdoBaselinePolicyDefinition[] = [
  {
    code: "MDO01",
    name: "Impersonation protection enabled",
    description: "Anti-phish policy protects key executives/domains from display-name and domain impersonation.",
    policyType: "AntiPhishing",
    riskMitigated: "Executive/brand impersonation phishing (CEO fraud, invoice fraud).",
    remediation: {
      cmdlet: "Set-AntiPhishPolicy",
      buildParameters: (policy) => ({
        Identity: policy.displayName,
        EnableTargetedUserProtection: true,
        EnableOrganizationDomainsProtection: true,
      }),
      summary: "Enables targeted user and organization-domain impersonation protection on the existing anti-phish policy.",
    },
  },
  {
    code: "MDO02",
    name: "Spoof intelligence enabled",
    description: "Anti-phish policy uses spoof intelligence to detect senders spoofing your domains or external domains.",
    policyType: "AntiPhishing",
    riskMitigated: "Domain spoofing used to impersonate trusted senders.",
    remediation: {
      cmdlet: "Set-AntiPhishPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, EnableSpoofIntelligence: true }),
      summary: "Enables spoof intelligence on the existing anti-phish policy.",
    },
  },
  {
    code: "MDO03",
    name: "Zero-hour Auto Purge — spam",
    description: "Inbound anti-spam policy retroactively removes delivered messages later confirmed as spam.",
    policyType: "AntiSpamInbound",
    riskMitigated: "Spam that evades filtering at time of delivery but is identified shortly after.",
    remediation: {
      cmdlet: "Set-HostedContentFilterPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, SpamZapEnabled: true }),
      summary: "Enables Zero-hour Auto Purge for spam on the existing inbound anti-spam policy.",
    },
  },
  {
    code: "MDO04",
    name: "Zero-hour Auto Purge — phishing",
    description: "Anti-phish policy retroactively removes delivered messages later confirmed as phishing.",
    policyType: "AntiPhishing",
    riskMitigated: "Phishing that evades filtering at time of delivery but is identified shortly after.",
    remediation: {
      cmdlet: "Set-AntiPhishPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, PhishZapEnabled: true }),
      summary: "Enables Zero-hour Auto Purge for phishing on the existing anti-phish policy.",
    },
  },
  {
    code: "MDO05",
    name: "Safe Links scans URLs in real time",
    description: "Safe Links policy actively scans URLs at time-of-click across email, Teams, and Office apps rather than only rewriting them.",
    policyType: "SafeLinks",
    riskMitigated: "Malicious links that are benign at delivery time but weaponized later (time-of-click attacks).",
    remediation: {
      cmdlet: "Set-SafeLinksPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, EnableSafeLinksForEmail: true, ScanUrls: true }),
      summary: "Enables real-time URL scanning for email on the existing Safe Links policy.",
    },
  },
  {
    code: "MDO06",
    name: "Safe Attachments actually blocks",
    description: "Safe Attachments policy is set to Block or Dynamic Delivery, not Allow/Monitor-only.",
    policyType: "SafeAttachments",
    riskMitigated: "Malware delivered as email attachments (the single most common MDO bypass: a policy that exists but doesn't actually block).",
    remediation: {
      cmdlet: "Set-SafeAttachmentPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, Action: "DynamicDelivery" }),
      summary: "Sets the existing Safe Attachments policy's action to Dynamic Delivery (scans while allowing recipients to read the message body).",
    },
  },
  {
    code: "MDO07",
    name: "Anti-malware common attachment filter enabled",
    description: "Anti-malware policy blocks known-dangerous file types (executables, scripts) regardless of scan result.",
    policyType: "AntiMalware",
    riskMitigated: "Executable/script-based malware delivered via file extension, independent of signature detection.",
    remediation: {
      cmdlet: "Set-MalwareFilterPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, EnableFileFilter: true }),
      summary: "Enables the common attachment type filter on the existing anti-malware policy.",
    },
  },
  {
    code: "MDO08",
    name: "Outbound spam admin notification",
    description: "Outbound anti-spam policy notifies an admin when a mailbox is suspected of sending spam.",
    policyType: "AntiSpamOutbound",
    riskMitigated: "Compromised mailboxes used to send spam/phishing internally or to external partners, undetected.",
    remediation: {
      cmdlet: "Set-HostedOutboundSpamFilterPolicy",
      buildParameters: (policy) => ({ Identity: policy.displayName, NotifyOutboundSpam: true }),
      summary: "Enables outbound spam admin notification on the existing outbound anti-spam policy.",
    },
  },
  {
    code: "MDO09",
    name: "Core policies apply organization-wide",
    description: "Anti-phish, anti-spam, Safe Links, and Safe Attachments policies cover the whole organization, not a scoped subset of mailboxes.",
    policyType: "AntiPhishing",
    riskMitigated: "A policy that looks correctly configured but only protects a fraction of mailboxes, leaving the rest on weaker defaults.",
    // No auto-fix: narrowing/widening a policy's assigned scope is a tenant-specific
    // judgment call (which users/groups belong in scope), not a single safe setting.
  },
];
