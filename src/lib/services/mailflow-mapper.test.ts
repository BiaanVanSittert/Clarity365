import { describe, it, expect } from "vitest";
import {
  extractEmailAddress,
  isExternalAddress,
  parseExchangeSizeToMB,
  mapMailboxItem,
  mapMailboxStatistics,
  mapFullAccessDelegations,
  mapSendAsDelegations,
  mapSendOnBehalfDelegations,
  mapMailboxAutoForward,
  mapInboxRule,
  mapTransportRule,
  mapMailflowTransportRule,
  mapAcceptedDomain,
  mapDkimStatus,
  mapConnector,
  mapRemoteDomainAutoForwardBlocked,
  mapExternalSenderTagEnabled,
} from "./mailflow-mapper";

describe("extractEmailAddress", () => {
  it("extracts the SMTP address from a 'Display Name <SMTP:address>' identity", () => {
    expect(extractEmailAddress("Jane Doe <SMTP:jane@contoso.com>")).toBe("jane@contoso.com");
  });

  it("returns a bare email address unchanged", () => {
    expect(extractEmailAddress("jane@contoso.com")).toBe("jane@contoso.com");
  });

  it("falls back to the raw string when no address can be parsed", () => {
    expect(extractEmailAddress("NT AUTHORITY\\SELF")).toBe("NT AUTHORITY\\SELF");
  });

  it("returns an empty string for null/undefined input", () => {
    expect(extractEmailAddress(undefined)).toBe("");
    expect(extractEmailAddress(null)).toBe("");
  });
});

describe("isExternalAddress", () => {
  it("treats a different domain as external", () => {
    expect(isExternalAddress("attacker@evil.com", "contoso.com")).toBe(true);
  });

  it("treats the tenant's own domain as internal, case-insensitively", () => {
    expect(isExternalAddress("jane@Contoso.com", "contoso.com")).toBe(false);
  });

  it("treats an unparseable address (no @) as not classifiable as external", () => {
    expect(isExternalAddress("some-legacy-dn-string", "contoso.com")).toBe(false);
  });
});

describe("parseExchangeSizeToMB", () => {
  it("parses the parenthesized byte count regardless of the displayed unit", () => {
    expect(parseExchangeSizeToMB("1.204 GB (1,293,942,784 bytes)")).toBe(Math.round(1293942784 / (1024 * 1024)));
  });

  it("returns 0 for missing or unparseable input", () => {
    expect(parseExchangeSizeToMB(undefined)).toBe(0);
    expect(parseExchangeSizeToMB("garbage")).toBe(0);
  });
});

describe("mapMailboxItem", () => {
  it("maps core mailbox fields and defaults hasDirectLicense/delegations for the caller to fill in", () => {
    const mbx = mapMailboxItem({
      ExchangeGuid: "guid-1",
      UserPrincipalName: "jane@contoso.com",
      DisplayName: "Jane Doe",
      RecipientTypeDetails: "SharedMailbox",
      ArchiveStatus: "Active",
    });
    expect(mbx).toEqual({
      id: "guid-1",
      userPrincipalName: "jane@contoso.com",
      displayName: "Jane Doe",
      recipientType: "SharedMailbox",
      totalItemSizeMB: 0,
      itemCount: 0,
      archiveStatus: "Enabled",
      hasDirectLicense: false,
      delegations: [],
    });
  });

  it("maps ArchiveStatus 'None' distinctly from 'Disabled'", () => {
    expect(mapMailboxItem({ UserPrincipalName: "x", ArchiveStatus: "None" }).archiveStatus).toBe("None");
    expect(mapMailboxItem({ UserPrincipalName: "x", ArchiveStatus: "SomethingElse" }).archiveStatus).toBe("Disabled");
  });
});

describe("mapMailboxStatistics", () => {
  it("maps size and item count", () => {
    expect(mapMailboxStatistics({ TotalItemSize: "2 GB (2,147,483,648 bytes)", ItemCount: 500 })).toEqual({
      totalItemSizeMB: 2048,
      itemCount: 500,
    });
  });
});

describe("mapFullAccessDelegations", () => {
  it("excludes self, inherited, and deny entries", () => {
    const result = mapFullAccessDelegations([
      { User: "NT AUTHORITY\\SELF", AccessRights: ["FullAccess"] },
      { User: "admin@contoso.com", AccessRights: ["FullAccess"], IsInherited: true },
      { User: "attacker@contoso.com", AccessRights: ["FullAccess"], Deny: true },
      { User: "delegate@contoso.com", AccessRights: ["FullAccess"] },
    ]);
    expect(result).toEqual([
      { principalDisplayName: "delegate@contoso.com", principalUserPrincipalName: "delegate@contoso.com", accessRight: "FullAccess", isInherited: false },
    ]);
  });
});

describe("mapSendAsDelegations", () => {
  it("excludes self and deny entries", () => {
    const result = mapSendAsDelegations([
      { Trustee: "NT AUTHORITY\\SELF", AccessControlType: "Allow" },
      { Trustee: "blocked@contoso.com", AccessControlType: "Deny" },
      { Trustee: "delegate@contoso.com", AccessControlType: "Allow" },
    ]);
    expect(result).toEqual([
      { principalDisplayName: "delegate@contoso.com", principalUserPrincipalName: "delegate@contoso.com", accessRight: "SendAs", isInherited: false },
    ]);
  });
});

describe("mapSendOnBehalfDelegations", () => {
  it("maps every identity in GrantSendOnBehalfTo", () => {
    expect(mapSendOnBehalfDelegations(["assistant@contoso.com"])).toEqual([
      { principalDisplayName: "assistant@contoso.com", principalUserPrincipalName: "assistant@contoso.com", accessRight: "SendOnBehalf", isInherited: false },
    ]);
  });

  it("returns an empty array when not an array", () => {
    expect(mapSendOnBehalfDelegations(undefined)).toEqual([]);
    expect(mapSendOnBehalfDelegations(null)).toEqual([]);
  });
});

describe("mapMailboxAutoForward", () => {
  it("returns null when no forwarding is configured", () => {
    expect(mapMailboxAutoForward({ UserPrincipalName: "jane@contoso.com" }, "contoso.com")).toBeNull();
  });

  it("flags external mailbox-level auto-forward as critical", () => {
    const rule = mapMailboxAutoForward(
      { UserPrincipalName: "jane@contoso.com", DisplayName: "Jane Doe", ForwardingSmtpAddress: "SMTP:jane.personal@gmail.com", DeliverToMailboxAndForward: true },
      "contoso.com"
    );
    expect(rule?.isExternal).toBe(true);
    expect(rule?.alertLevel).toBe("critical");
    expect(rule?.ruleAction).toBe("ForwardTo");
    expect(rule?.forwardingAddress).toBe("jane.personal@gmail.com");
  });

  it("marks DeliverToMailboxAndForward:false as a redirect, not a forward", () => {
    const rule = mapMailboxAutoForward(
      { UserPrincipalName: "jane@contoso.com", ForwardingSmtpAddress: "jane@partner.com", DeliverToMailboxAndForward: false },
      "contoso.com"
    );
    expect(rule?.ruleAction).toBe("RedirectTo");
  });

  it("does not flag internal auto-forward as critical", () => {
    const rule = mapMailboxAutoForward({ UserPrincipalName: "jane@contoso.com", ForwardingSmtpAddress: "team@contoso.com" }, "contoso.com");
    expect(rule?.isExternal).toBe(false);
    expect(rule?.alertLevel).toBe("info");
  });
});

describe("mapInboxRule", () => {
  it("returns null for rules with no forward/redirect action", () => {
    expect(mapInboxRule({ Name: "Move to folder", MoveToFolder: "Archive" }, "jane@contoso.com", "contoso.com")).toBeNull();
  });

  it("flags an enabled external inbox rule as critical", () => {
    const rule = mapInboxRule(
      { Name: "Auto-forward invoices", ForwardTo: "SMTP:attacker@evil.com", Enabled: true },
      "jane@contoso.com",
      "contoso.com"
    );
    expect(rule?.isExternal).toBe(true);
    expect(rule?.state).toBe("Enabled");
    expect(rule?.alertLevel).toBe("critical");
    expect(rule?.mailboxOwner).toBe("jane@contoso.com");
  });

  it("downgrades a disabled external rule to warning, not critical", () => {
    const rule = mapInboxRule({ Name: "Old rule", RedirectTo: "attacker@evil.com", Enabled: false }, "jane@contoso.com", "contoso.com");
    expect(rule?.state).toBe("Disabled");
    expect(rule?.alertLevel).toBe("warning");
    expect(rule?.ruleAction).toBe("RedirectTo");
  });
});

describe("mapTransportRule", () => {
  it("returns null for rules with no redirect/bcc/copy action", () => {
    expect(mapTransportRule({ Name: "Add disclaimer", ApplyHtmlDisclaimerText: "..." }, "contoso.com")).toBeNull();
  });

  it("flags an enabled external BlindCopyTo rule as critical", () => {
    const rule = mapTransportRule({ Name: "BCC invoices", BlindCopyTo: "attacker@evil.com", State: "Enabled" }, "contoso.com");
    expect(rule?.isExternal).toBe(true);
    expect(rule?.ruleAction).toBe("Bcc");
    expect(rule?.alertLevel).toBe("critical");
  });

  it("maps a disabled rule's state correctly", () => {
    const rule = mapTransportRule({ Name: "Old redirect", RedirectMessageTo: "attacker@evil.com", State: "Disabled" }, "contoso.com");
    expect(rule?.state).toBe("Disabled");
    expect(rule?.alertLevel).toBe("warning");
  });
});

describe("mapMailflowTransportRule", () => {
  it("flags an external redirect", () => {
    const rule = mapMailflowTransportRule({ Name: "Redirect", RedirectMessageTo: "attacker@evil.com", State: "Enabled" }, "contoso.com");
    expect(rule.redirectsExternally).toBe(true);
    expect(rule.externalRedirectAddress).toBe("attacker@evil.com");
  });

  it("does not flag an internal redirect as external", () => {
    const rule = mapMailflowTransportRule({ Name: "Redirect", RedirectMessageTo: "team@contoso.com" }, "contoso.com");
    expect(rule.redirectsExternally).toBe(false);
    expect(rule.externalRedirectAddress).toBeUndefined();
  });

  it("flags SetSCL as a spam-confidence override", () => {
    expect(mapMailflowTransportRule({ Name: "Whitelist", SetSCL: "-1" }, "contoso.com").overridesSpamConfidence).toBe(true);
    expect(mapMailflowTransportRule({ Name: "Normal" }, "contoso.com").overridesSpamConfidence).toBe(false);
  });

  it("treats a rule with no recognized scoping conditions as unscoped", () => {
    expect(mapMailflowTransportRule({ Name: "Disclaimer" }, "contoso.com").hasNoScopingConditions).toBe(true);
    expect(
      mapMailflowTransportRule({ Name: "Scoped", SenderDomainIs: ["partner.com"] }, "contoso.com").hasNoScopingConditions
    ).toBe(false);
  });

  it("maps expiry and disabled state", () => {
    const rule = mapMailflowTransportRule({ Name: "Temp rule", State: "Disabled", ExpiryDate: "2026-12-31" }, "contoso.com");
    expect(rule.hasExpiry).toBe(true);
    expect(rule.state).toBe("Disabled");
  });
});

describe("mapAcceptedDomain", () => {
  it("maps the domain name and default flag, lowercased", () => {
    expect(mapAcceptedDomain({ DomainName: "Contoso.com", Default: true })).toEqual({ domain: "contoso.com", isDefaultDomain: true });
    expect(mapAcceptedDomain({ DomainName: "sub.contoso.com" })).toEqual({ domain: "sub.contoso.com", isDefaultDomain: false });
  });
});

describe("mapDkimStatus", () => {
  it("fails when DKIM is not enabled", () => {
    expect(mapDkimStatus({ Enabled: false }).status).toBe("fail");
  });

  it("warns when enabled but DNS status isn't valid", () => {
    const result = mapDkimStatus({ Enabled: true, Status: "CnameMissing" });
    expect(result.status).toBe("warn");
    expect(result.detail).toContain("CnameMissing");
  });

  it("passes when enabled and valid", () => {
    expect(mapDkimStatus({ Enabled: true, Status: "Valid" }).status).toBe("pass");
  });
});

describe("mapConnector", () => {
  it("flags an inbound connector with a wildcard sender domain and no IP restriction as trusting anonymous senders", () => {
    const connector = mapConnector({ Name: "Legacy Partner", SenderDomains: ["*"], RestrictDomainsToIPAddresses: false }, "Inbound");
    expect(connector.trustsAnonymousSenders).toBe(true);
  });

  it("does not flag a connector that restricts by IP", () => {
    const connector = mapConnector({ Name: "Partner", SenderDomains: ["*"], RestrictDomainsToIPAddresses: true }, "Inbound");
    expect(connector.trustsAnonymousSenders).toBe(false);
  });

  it("never flags an outbound connector as trusting anonymous senders", () => {
    const connector = mapConnector({ Name: "Outbound", SenderDomains: ["*"] }, "Outbound");
    expect(connector.trustsAnonymousSenders).toBe(false);
  });

  it("maps requiresTls", () => {
    expect(mapConnector({ Name: "X", RequireTls: true }, "Inbound").requiresTls).toBe(true);
    expect(mapConnector({ Name: "X" }, "Inbound").requiresTls).toBe(false);
  });
});

describe("mapRemoteDomainAutoForwardBlocked", () => {
  it("is true only when AutoForwardEnabled is exactly false", () => {
    expect(mapRemoteDomainAutoForwardBlocked({ AutoForwardEnabled: false })).toBe(true);
    expect(mapRemoteDomainAutoForwardBlocked({ AutoForwardEnabled: true })).toBe(false);
    expect(mapRemoteDomainAutoForwardBlocked({})).toBe(false);
  });
});

describe("mapExternalSenderTagEnabled", () => {
  it("is true only when Enabled is exactly true", () => {
    expect(mapExternalSenderTagEnabled({ Enabled: true })).toBe(true);
    expect(mapExternalSenderTagEnabled({ Enabled: false })).toBe(false);
    expect(mapExternalSenderTagEnabled({})).toBe(false);
  });
});
