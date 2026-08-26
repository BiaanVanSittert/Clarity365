import { MailboxItem, MailboxDelegation, EmailForwardingRule, MailflowTransportRule, DomainAuthCheck, MailflowConnector } from "../types";

// Maps raw Exchange Online PowerShell cmdlet output (via exo-client.ts's
// InvokeCommand REST surface, same mechanism mdo-mapper.ts uses) into
// Clarity365's mailbox/delegation/forwarding-rule shapes. Field names below
// are based on the documented Get-Mailbox / Get-MailboxStatistics /
// Get-MailboxPermission / Get-RecipientPermission / Get-InboxRule /
// Get-TransportRule cmdlets as of this writing — worth confirming against a
// live tenant's actual JSON shape during real testing, the same honesty
// caveat mdo-mapper.ts's header already applies to its own EXO field
// assumptions.
//
// isExternal below is a single-domain heuristic (compares against the
// tenant's own default domain only) — a tenant with multiple accepted
// domains (subsidiaries, vanity domains) will see inter-company forwarding
// misclassified as external until Phase 2 wires in the real accepted-domain
// list via Get-AcceptedDomain.

function isSelfPrincipal(identity: string | undefined | null): boolean {
  return !!identity && identity.trim().toUpperCase() === "NT AUTHORITY\\SELF";
}

// Extracts a bare email address from an Exchange identity string, which can
// come back as a plain SMTP address, a "Display Name <SMTP:address>" form,
// or occasionally a legacy Exchange DN with no parseable address at all (in
// which case the original raw string is returned unchanged).
export function extractEmailAddress(raw: string | undefined | null): string {
  if (!raw) return "";
  const smtpMatch = raw.match(/SMTP:([^\s>]+)/i);
  if (smtpMatch) return smtpMatch[1];
  const bareMatch = raw.match(/[^\s<>]+@[^\s<>]+/);
  return bareMatch ? bareMatch[0] : raw;
}

export function isExternalAddress(address: string, tenantDomain: string): boolean {
  const at = address.lastIndexOf("@");
  if (at === -1) return false; // not a resolvable SMTP address (e.g. an unresolved legacy DN) — can't classify as external
  const domain = address.slice(at + 1).toLowerCase();
  return domain.length > 0 && domain !== tenantDomain.toLowerCase();
}

// Exchange reports mailbox size as e.g. "1.204 GB (1,293,942,784 bytes)" —
// the parenthesized byte count is the only part that parses reliably across
// unit variations (KB/MB/GB/TB).
export function parseExchangeSizeToMB(raw: string | undefined | null): number {
  if (!raw) return 0;
  const bytesMatch = raw.match(/\(([\d,]+)\s*bytes\)/i);
  if (!bytesMatch) return 0;
  const bytes = parseInt(bytesMatch[1].replace(/,/g, ""), 10);
  return isNaN(bytes) ? 0 : Math.round(bytes / (1024 * 1024));
}

// hasDirectLicense is deliberately left false here — Get-Mailbox has no
// license concept at all; the caller (graph-client.ts) cross-references the
// license data it already fetches from Graph for Module 5 (user
// classification) rather than this app making a second, redundant call for
// the same information.
export function mapMailboxItem(raw: any): MailboxItem {
  return {
    id: raw.ExchangeGuid || raw.Guid || raw.UserPrincipalName || raw.Name,
    userPrincipalName: raw.UserPrincipalName || raw.PrimarySmtpAddress || "",
    displayName: raw.DisplayName || raw.Name || raw.UserPrincipalName || "Unknown Mailbox",
    recipientType: (raw.RecipientTypeDetails as MailboxItem["recipientType"]) || "UserMailbox",
    totalItemSizeMB: 0,
    itemCount: 0,
    archiveStatus: raw.ArchiveStatus === "Active" ? "Enabled" : raw.ArchiveStatus === "None" ? "None" : "Disabled",
    hasDirectLicense: false,
    delegations: [],
  };
}

export function mapMailboxStatistics(raw: any): { totalItemSizeMB: number; itemCount: number } {
  return {
    totalItemSizeMB: parseExchangeSizeToMB(raw?.TotalItemSize),
    itemCount: typeof raw?.ItemCount === "number" ? raw.ItemCount : 0,
  };
}

export function mapFullAccessDelegations(rows: any[]): MailboxDelegation[] {
  return (rows || [])
    .filter((r) => !isSelfPrincipal(r.User) && !r.IsInherited && !r.Deny)
    .map((r) => ({
      principalDisplayName: r.User || "Unknown",
      principalUserPrincipalName: extractEmailAddress(r.User) || r.User,
      accessRight: "FullAccess" as const,
      isInherited: !!r.IsInherited,
    }));
}

export function mapSendAsDelegations(rows: any[]): MailboxDelegation[] {
  return (rows || [])
    .filter((r) => !isSelfPrincipal(r.Trustee) && r.AccessControlType !== "Deny")
    .map((r) => ({
      principalDisplayName: r.Trustee || "Unknown",
      principalUserPrincipalName: extractEmailAddress(r.Trustee) || r.Trustee,
      accessRight: "SendAs" as const,
      // Get-RecipientPermission doesn't expose an inheritance concept the
      // way Get-MailboxPermission does for FullAccess.
      isInherited: false,
    }));
}

export function mapSendOnBehalfDelegations(grantSendOnBehalfTo: string[] | undefined | null): MailboxDelegation[] {
  if (!Array.isArray(grantSendOnBehalfTo)) return [];
  return grantSendOnBehalfTo.map((identity) => ({
    principalDisplayName: identity,
    principalUserPrincipalName: extractEmailAddress(identity) || identity,
    accessRight: "SendOnBehalf" as const,
    isInherited: false,
  }));
}

// Mailbox-level auto-forward (Set-Mailbox -ForwardingSmtpAddress / -ForwardingAddress)
// is a distinct exfiltration vector from inbox rules — a single tenant-wide
// mailbox setting rather than a rule an attacker has to plant.
export function mapMailboxAutoForward(raw: any, tenantDomain: string): EmailForwardingRule | null {
  const configured = raw.ForwardingSmtpAddress || raw.ForwardingAddress;
  if (!configured) return null;
  const address = extractEmailAddress(configured);
  const external = isExternalAddress(address, tenantDomain);
  return {
    id: `smtp-fwd-${raw.ExchangeGuid || raw.UserPrincipalName}`,
    scope: "smtp_forward",
    name: `Mailbox-level auto-forward: ${raw.DisplayName || raw.UserPrincipalName}`,
    mailboxOwner: raw.UserPrincipalName,
    forwardingAddress: address,
    isExternal: external,
    // DeliverToMailboxAndForward === false means the original stays out of
    // the mailbox entirely — a straight redirect rather than a copy-forward.
    ruleAction: raw.DeliverToMailboxAndForward === false ? "RedirectTo" : "ForwardTo",
    state: "Enabled",
    dateCreated: new Date().toISOString(),
    alertLevel: external ? "critical" : "info",
  };
}

// Only inbox rules whose action actually forwards/redirects/copies mail are
// relevant here — most inbox rules (move to folder, mark as read, etc.)
// aren't forwarding vectors at all and are intentionally excluded (returns
// null).
export function mapInboxRule(raw: any, mailboxOwner: string, tenantDomain: string): EmailForwardingRule | null {
  const target = raw.ForwardTo || raw.ForwardAsAttachmentTo || raw.RedirectTo;
  if (!target) return null;
  const targets = Array.isArray(target) ? target : [target];
  const address = extractEmailAddress(targets[0]);
  const ruleAction: EmailForwardingRule["ruleAction"] = raw.ForwardAsAttachmentTo
    ? "ForwardAsAttachmentTo"
    : raw.RedirectTo
    ? "RedirectTo"
    : "ForwardTo";
  const enabled = raw.Enabled !== false;
  const external = isExternalAddress(address, tenantDomain);
  return {
    id: `inbox-${mailboxOwner}-${raw.Identity || raw.Name}`,
    scope: "inbox_rule",
    name: raw.Name || "Unnamed inbox rule",
    mailboxOwner,
    forwardingAddress: address,
    isExternal: external,
    ruleAction,
    state: enabled ? "Enabled" : "Disabled",
    dateCreated: new Date().toISOString(),
    alertLevel: external && enabled ? "critical" : external ? "warning" : "info",
  };
}

// Org-wide transport rules whose action redirects/BCCs/copies mail — the
// same "only forwarding-shaped actions matter" filter as inbox rules above.
export function mapTransportRule(raw: any, tenantDomain: string): EmailForwardingRule | null {
  const target = raw.RedirectMessageTo || raw.BlindCopyTo || raw.CopyTo;
  if (!target) return null;
  const targets = Array.isArray(target) ? target : [target];
  const address = extractEmailAddress(targets[0]);
  const ruleAction: EmailForwardingRule["ruleAction"] = raw.RedirectMessageTo
    ? "RedirectTo"
    : raw.BlindCopyTo
    ? "Bcc"
    : "ForwardTo";
  const enabled = raw.State !== "Disabled";
  const external = isExternalAddress(address, tenantDomain);
  return {
    id: `transport-${raw.Guid || raw.Identity || raw.Name}`,
    scope: "transport_rule",
    name: raw.Name || "Unnamed transport rule",
    forwardingAddress: address,
    isExternal: external,
    ruleAction,
    state: enabled ? "Enabled" : "Disabled",
    dateCreated: raw.WhenCreated || new Date().toISOString(),
    alertLevel: external && enabled ? "critical" : external ? "warning" : "info",
  };
}

// A small set of the most common Get-TransportRule condition parameters —
// Exchange has dozens of possible ones, so this isn't exhaustive. If none of
// these are set, the rule applies to all mail with no scoping at all, which
// is the "broad, permanent rule" pattern the Mail Flow Rules baseline (MF03)
// flags for review — worth confirming this list against a live tenant's
// actual rules, same caveat as the rest of this file.
const SCOPING_CONDITION_FIELDS = [
  "From",
  "FromScope",
  "SentTo",
  "SentToScope",
  "SenderDomainIs",
  "RecipientDomainIs",
  "SubjectContainsWords",
  "SubjectOrBodyContainsWords",
  "HeaderContainsMessageHeader",
  "ExceptIfFrom",
  "ExceptIfSentTo",
];

// Full-fidelity mapping of a transport rule for the Mail Flow Rules
// baseline, as opposed to mapTransportRule above which only captures the
// forwarding-shaped subset for the Email Forwarding Audit module. A rule can
// be flagged here (e.g. an SCL override) without ever appearing there.
export function mapMailflowTransportRule(raw: any, tenantDomain: string): MailflowTransportRule {
  const redirectTarget = raw.RedirectMessageTo || raw.BlindCopyTo || raw.CopyTo;
  const targets = redirectTarget ? (Array.isArray(redirectTarget) ? redirectTarget : [redirectTarget]) : [];
  const address = targets.length > 0 ? extractEmailAddress(targets[0]) : undefined;
  const redirectsExternally = !!address && isExternalAddress(address, tenantDomain);

  const hasNoScopingConditions = !SCOPING_CONDITION_FIELDS.some((field) => {
    const value = raw[field];
    return Array.isArray(value) ? value.length > 0 : !!value;
  });

  return {
    id: raw.Guid || raw.Identity || raw.Name,
    name: raw.Name || "Unnamed transport rule",
    state: raw.State === "Disabled" ? "Disabled" : "Enabled",
    redirectsExternally,
    externalRedirectAddress: redirectsExternally ? address : undefined,
    overridesSpamConfidence: raw.SetSCL !== undefined && raw.SetSCL !== null && raw.SetSCL !== "",
    hasNoScopingConditions,
    hasExpiry: !!raw.ExpiryDate,
  };
}

export function mapAcceptedDomain(raw: any): { domain: string; isDefaultDomain: boolean } {
  return { domain: (raw.DomainName || raw.Name || "").toLowerCase(), isDefaultDomain: !!raw.Default };
}

// Get-DkimSigningConfig's Status property (e.g. "Valid", "CnameMissing",
// "SelectorBroken", "CouldNotCheckDnsRecords") reports whether the CNAME
// selector records Exchange expects are actually published and correct —
// worth confirming the exact status string values against a live tenant,
// same caveat as the rest of this file's EXO field assumptions.
export function mapDkimStatus(raw: any): DomainAuthCheck {
  const enabled = !!raw.Enabled;
  if (!enabled) {
    return {
      status: "fail",
      detail: "DKIM signing is not enabled for this domain.",
      recommendation: "Run Enable-DkimSigningConfig, then publish the two CNAME selector records Exchange provides at your DNS host.",
    };
  }
  const status = typeof raw.Status === "string" ? raw.Status : undefined;
  if (status && status.toLowerCase() !== "valid") {
    return {
      status: "warn",
      detail: `DKIM signing is enabled but Exchange reports its DNS records as "${status}" rather than valid — the CNAME selector records may not be published yet.`,
      recommendation: "Verify both DKIM CNAME selector records are published at your DNS host and match what Get-DkimSigningConfig expects.",
    };
  }
  return { status: "pass", detail: "DKIM signing is enabled and its DNS records are valid." };
}

// "Trusts anonymous senders" here means SenderDomains includes a wildcard
// with no IP restriction — Microsoft's own guidance flags this as the
// classic misconfiguration where a connector set up for a vendor/hybrid
// integration ends up letting anyone spoof that domain past all filtering.
// Worth confirming this heuristic against a live tenant's real connectors,
// same caveat as the rest of this file.
export function mapConnector(raw: any, direction: "Inbound" | "Outbound"): MailflowConnector {
  const senderDomains: string[] = Array.isArray(raw.SenderDomains)
    ? raw.SenderDomains
    : raw.SenderDomains
    ? [raw.SenderDomains]
    : [];
  return {
    id: raw.Guid || raw.Identity || raw.Name,
    name: raw.Name || "Unnamed connector",
    direction,
    enabled: raw.Enabled !== false,
    trustsAnonymousSenders: direction === "Inbound" && senderDomains.includes("*") && raw.RestrictDomainsToIPAddresses !== true,
    requiresTls: !!raw.RequireTls,
  };
}

export function mapRemoteDomainAutoForwardBlocked(raw: any): boolean {
  return raw?.AutoForwardEnabled === false;
}

export function mapExternalSenderTagEnabled(raw: any): boolean {
  return raw?.Enabled === true;
}
