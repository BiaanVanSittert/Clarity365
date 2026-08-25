import { describe, it, expect } from "vitest";
import { mapMdoPolicy, mapTablEntry, mapEntryTypeToListType } from "./mdo-mapper";

describe("mapEntryTypeToListType", () => {
  it("maps url and file_hash to their own EXO ListType", () => {
    expect(mapEntryTypeToListType("url")).toBe("Url");
    expect(mapEntryTypeToListType("file_hash")).toBe("FileHash");
  });

  it("maps both domain and sender to EXO's Sender ListType", () => {
    expect(mapEntryTypeToListType("domain")).toBe("Sender");
    expect(mapEntryTypeToListType("sender")).toBe("Sender");
  });
});

describe("mapMdoPolicy", () => {
  it("maps an enabled anti-phish policy with impersonation and spoof protection active", () => {
    const policy = mapMdoPolicy(
      {
        Guid: "guid-1",
        Name: "Default Anti-Phish Policy",
        Enabled: true,
        EnableTargetedUserProtection: true,
        EnableSpoofIntelligence: true,
      },
      "AntiPhishing"
    );
    expect(policy).toEqual({
      id: "guid-1",
      policyType: "AntiPhishing",
      displayName: "Default Anti-Phish Policy",
      state: "Enabled",
      assignedScope: "Default (Organization-wide)",
      impersonationProtection: true,
      spoofIntelligence: true,
      zapEnabled: false,
      complianceRating: "compliant",
      realTimeScanning: false,
      blockingAction: false,
      commonAttachmentFilter: false,
      outboundNotify: false,
    });
  });

  it("marks a disabled policy as critical regardless of its configured protections", () => {
    const policy = mapMdoPolicy({ Name: "Custom Policy", Enabled: false, EnableSpoofIntelligence: true }, "AntiPhishing");
    expect(policy.state).toBe("Disabled");
    expect(policy.complianceRating).toBe("critical");
  });

  it("treats Safe Links/Safe Attachments as protective simply by existing, even with no anti-phish flags", () => {
    const safeLinks = mapMdoPolicy({ Name: "Default Safe Links", Enabled: true }, "SafeLinks");
    expect(safeLinks.complianceRating).toBe("compliant");
  });

  it("marks an enabled policy with no active protections as substandard", () => {
    const policy = mapMdoPolicy({ Name: "Weak Policy", Enabled: true }, "AntiSpamInbound");
    expect(policy.complianceRating).toBe("substandard");
  });

  it("derives a scoped assignment string from recipient-targeting fields", () => {
    const policy = mapMdoPolicy(
      { Name: "Finance Policy", Enabled: true, RecipientDomainIs: ["finance.contoso.com"] },
      "AntiPhishing"
    );
    expect(policy.assignedScope).toBe("finance.contoso.com");
  });

  it("falls back to a stable id derived from policyType when no identifier fields are present", () => {
    const policy = mapMdoPolicy({}, "AntiMalware");
    expect(policy.id).toBe("AntiMalware");
    expect(policy.displayName).toBe("AntiMalware");
  });

  it("only counts Safe Links real-time scanning when both the email switch and URL scan are on", () => {
    expect(mapMdoPolicy({ EnableSafeLinksForEmail: true, ScanUrls: true }, "SafeLinks").realTimeScanning).toBe(true);
    expect(mapMdoPolicy({ EnableSafeLinksForEmail: true, ScanUrls: false }, "SafeLinks").realTimeScanning).toBe(false);
    expect(mapMdoPolicy({ ScanUrls: true }, "SafeLinks").realTimeScanning).toBe(false);
  });

  it("treats Safe Attachments Block or DynamicDelivery as a real blocking action, but not Allow/Monitor", () => {
    expect(mapMdoPolicy({ Action: "Block" }, "SafeAttachments").blockingAction).toBe(true);
    expect(mapMdoPolicy({ Action: "DynamicDelivery" }, "SafeAttachments").blockingAction).toBe(true);
    expect(mapMdoPolicy({ Action: "Allow" }, "SafeAttachments").blockingAction).toBe(false);
    expect(mapMdoPolicy({ Action: "Monitor" }, "SafeAttachments").blockingAction).toBe(false);
  });

  it("maps the anti-malware common attachment filter and outbound spam notification flags", () => {
    expect(mapMdoPolicy({ EnableFileFilter: true }, "AntiMalware").commonAttachmentFilter).toBe(true);
    expect(mapMdoPolicy({}, "AntiMalware").commonAttachmentFilter).toBe(false);
    expect(mapMdoPolicy({ NotifyOutboundSpam: true }, "AntiSpamOutbound").outboundNotify).toBe(true);
    expect(mapMdoPolicy({}, "AntiSpamOutbound").outboundNotify).toBe(false);
  });
});

describe("mapTablEntry", () => {
  it("maps a Sender-list block entry, inferring 'sender' entryType from an email-shaped value", () => {
    const entry = mapTablEntry(
      { Identity: "entry-1", Value: "fraud@evil.com", Action: "Block", LastModifiedDateTime: "2026-08-01T00:00:00Z" },
      "Sender"
    );
    expect(entry).toEqual({
      id: "entry-1",
      listType: "block",
      entryType: "sender",
      value: "fraud@evil.com",
      addedBy: "Exchange Online",
      dateAdded: "2026-08-01T00:00:00Z",
      expirationDate: "Never",
      notes: "",
    });
  });

  it("infers 'domain' entryType for a Sender-list value with no @ sign", () => {
    const entry = mapTablEntry({ Value: "malicious-phish.net", Action: "Block" }, "Sender");
    expect(entry.entryType).toBe("domain");
  });

  it("maps Url and FileHash list types directly", () => {
    expect(mapTablEntry({ Value: "https://bad-login.xyz" }, "Url").entryType).toBe("url");
    expect(mapTablEntry({ Value: "abc123" }, "FileHash").entryType).toBe("file_hash");
  });

  it("defaults to 'block' unless the action is explicitly Allow", () => {
    expect(mapTablEntry({ Value: "x", Action: "Allow" }, "Sender").listType).toBe("allow");
    expect(mapTablEntry({ Value: "x" }, "Sender").listType).toBe("block");
  });

  it("notes a lack of expiration when NoExpiration is set and no explicit notes exist", () => {
    expect(mapTablEntry({ Value: "x", NoExpiration: true }, "Sender").notes).toBe("No expiration configured.");
    expect(mapTablEntry({ Value: "x", Notes: "Reported by SOC." }, "Sender").notes).toBe("Reported by SOC.");
  });
});
