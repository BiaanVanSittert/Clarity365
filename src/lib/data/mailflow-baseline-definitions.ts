// Mirrors mdo-baseline-definitions.ts's pattern for the Transport & Mail
// Flow Rules category: MF01-03 score every org-wide transport rule against a
// known real-world abuse pattern (one result per check, listing every
// offending rule by name so an admin can judge intent before disabling);
// MF04 scores a single tenant-wide setting (AutoForwardingMode on the
// outbound spam policy - already fetched for MDO Module 8, see
// mdo-mapper.ts's autoForwardingBlocked field, so no new EXO call is needed
// for that one check).
//
// A planned "rule disables malware/attachment scanning" check was folded
// into MF02 rather than shipped separately - Exchange transport rules don't
// have a distinct action for that; the real mechanism is the same SCL
// override MF02 already covers.

export interface MailflowRemediationAction {
  cmdlet: string;
  buildParameters: (ruleName: string) => Record<string, any>;
  summary: string;
}

export interface MailflowBaselineCheck {
  code: string;
  name: string;
  description: string;
  riskMitigated: string;
  // Absent for checks that are inherently a judgment call rather than a
  // safe default (MF03) - same "no auto-fix" convention as
  // mdo-baseline-definitions.ts's MDO09.
  remediation?: MailflowRemediationAction;
}

export const MAILFLOW_BASELINE_STANDARDS: MailflowBaselineCheck[] = [
  {
    code: "MF01",
    name: "No transport rule redirects mail externally",
    description:
      "No enabled organization-wide transport rule silently redirects, BCCs, or copies mail to an external address.",
    riskMitigated:
      "A compromised admin account (or malicious insider) planting a rule that silently exfiltrates mail matching a keyword - persists even after the original account compromise is fixed.",
    remediation: {
      cmdlet: "Disable-TransportRule",
      buildParameters: (ruleName) => ({ Identity: ruleName, Confirm: false }),
      summary: "Disables the flagged transport rule.",
    },
  },
  {
    code: "MF02",
    name: "No transport rule overrides spam/phish filtering",
    description:
      "No enabled transport rule sets a Spam Confidence Level (SCL) override, which forces mail from a whitelisted sender/domain to bypass anti-spam and anti-phish filtering entirely - the same mechanism that would be used to disable content scanning for a scope.",
    riskMitigated:
      "Phishing or malware from a spoofed 'trusted partner' domain guaranteed to land in the inbox because a rule marks it as pre-trusted.",
    remediation: {
      cmdlet: "Disable-TransportRule",
      buildParameters: (ruleName) => ({ Identity: ruleName, Confirm: false }),
      summary: "Disables the flagged transport rule.",
    },
  },
  {
    code: "MF03",
    name: "No unscoped, permanent transport rule",
    description:
      "Enabled transport rules that apply to all mail with no sender/recipient/domain scoping and no expiry date are the ones attackers hide inside - flagged for manual review rather than auto-disabled, since a broad rule (e.g. a company-wide disclaimer) is sometimes legitimate business configuration.",
    riskMitigated:
      "An overly broad, permanent rule masking a malicious one, or simply an unreviewed rule nobody remembers the purpose of.",
  },
  {
    code: "MF04",
    name: "Tenant-wide auto-forwarding is blocked",
    description:
      "The outbound spam policy's AutoForwardingMode is set to Off - the single tenant-wide switch controlling whether any mailbox can auto-forward to an external address at all.",
    riskMitigated:
      "Every individual auto-forward vector tracked in the Email Forwarding Audit module becomes possible again the moment this is left on - it's the kill switch behind all of them.",
    remediation: {
      cmdlet: "Set-HostedOutboundSpamFilterPolicy",
      buildParameters: () => ({ Identity: "Default", AutoForwardingMode: "Off" }),
      summary: "Disables tenant-wide auto-forwarding to external addresses.",
    },
  },
  {
    code: "MF05",
    name: "No inbound connector blanket-trusts anonymous senders",
    description:
      "No inbound connector treats all mail claiming to be from a given domain as pre-authenticated regardless of sending IP - flagged for manual review rather than auto-disabled, since removing a connector's trust configuration without knowing what still depends on it can break legitimate mail flow.",
    riskMitigated:
      "A connector set up years ago for a vendor/hybrid integration, still wide open, letting anyone spoof that domain past all spam/phish filtering.",
  },
  {
    code: "MF06",
    name: "Connectors enforce TLS",
    description:
      "Every inbound/outbound connector requires TLS, so partner mail doesn't flow unencrypted - flagged for manual review rather than auto-enabled, since a legacy connector without TLS support would simply stop delivering mail if forced on blind.",
    riskMitigated: "Mail to/from a partner organization transmitted in plaintext, interceptable in transit.",
  },
  {
    code: "MF07",
    name: "Org-wide remote-domain auto-forward is blocked",
    description:
      "The default remote domain's AutoForwardEnabled is off - a second, more obscure org-wide auto-forward switch (distinct from MF04's outbound-spam one) that most admins have never seen.",
    riskMitigated:
      "Every individual auto-forward vector becomes possible again if this switch alone is left on, even with MF04 fixed.",
    remediation: {
      cmdlet: "Set-RemoteDomain",
      buildParameters: () => ({ Identity: "Default", AutoForwardEnabled: false }),
      summary: "Disables auto-forwarding on the default remote domain.",
    },
  },
  {
    code: "MF08",
    name: "External sender warning tag is enabled",
    description:
      "Outlook shows a \"this message is from an external sender\" banner - one of the highest-ROI anti-phishing UX controls available, and frequently off by default.",
    riskMitigated: "Users can't visually distinguish an internal colleague from an external impersonator at a glance.",
    remediation: {
      cmdlet: "Set-ExternalInOutlook",
      buildParameters: () => ({ Enabled: true }),
      summary: "Enables the external sender warning tag tenant-wide.",
    },
  },
];
