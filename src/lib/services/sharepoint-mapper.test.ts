import { describe, it, expect } from "vitest";
import { detectSensitiveDataHeuristic, inferSiteTemplate, mapSharePointSite, mapTenantSharingSettings } from "./sharepoint-mapper";
import { TenantGroup } from "../types";

describe("detectSensitiveDataHeuristic", () => {
  it("flags sites whose name/URL contains a sensitive keyword", () => {
    expect(detectSensitiveDataHeuristic("HR Payroll Archive", "https://contoso.sharepoint.com/sites/hr")).toBe(true);
    expect(detectSensitiveDataHeuristic("Clinical Trial Data", "https://contoso.sharepoint.com/sites/trials")).toBe(true);
  });

  it("does not flag an ordinary site name", () => {
    expect(detectSensitiveDataHeuristic("Marketing Assets", "https://contoso.sharepoint.com/sites/marketing")).toBe(false);
  });
});

describe("inferSiteTemplate", () => {
  it("detects a OneDrive personal site from its URL", () => {
    expect(inferSiteTemplate({ webUrl: "https://contoso-my.sharepoint.com/personal/jane_contoso_com" })).toBe("PersonalOneDrive");
  });

  it("treats a group-connected site as a TeamSite", () => {
    expect(inferSiteTemplate({ webUrl: "https://contoso.sharepoint.com/sites/x", sharepointIds: { groupId: "g1" } })).toBe("TeamSite");
  });

  it("defaults ungrouped sites to CommunicationSite", () => {
    expect(inferSiteTemplate({ webUrl: "https://contoso.sharepoint.com/sites/comms" })).toBe("CommunicationSite");
  });
});

describe("mapSharePointSite", () => {
  it("converts drive quota bytes to GB and resolves the owner from the connected group", () => {
    const group: TenantGroup = {
      id: "g1",
      displayName: "Finance Team",
      mailNickname: "finance",
      groupType: "M365Unified",
      membershipType: "Assigned",
      ownersCount: 1,
      membersCount: 1,
      owners: ["owner@contoso.com"],
      members: [],
      isPrivileged: false,
      syncSource: "Cloud",
      createdDateTime: new Date().toISOString(),
      isAssignableToRole: false,
      guestMemberCount: 0,
    };
    const site = mapSharePointSite(
      { id: "s1", displayName: "Finance", webUrl: "https://contoso.sharepoint.com/sites/finance", sharepointIds: { groupId: "g1" } },
      { used: 1024 * 1024 * 1024 * 2, total: 1024 * 1024 * 1024 * 10 },
      "ExistingGuests",
      new Map([["g1", group]])
    );
    expect(site.storageUsedGB).toBe(2);
    expect(site.storageAllocatedGB).toBe(10);
    expect(site.ownerUPN).toBe("owner@contoso.com");
    expect(site.sharingCapability).toBe("ExistingGuests");
    expect(site.isSensitiveDataPresent).toBe(true); // "Finance" keyword
  });

  it("leaves ownerUPN blank when there's no connected group", () => {
    const site = mapSharePointSite({ id: "s2", displayName: "Comms", webUrl: "https://contoso.sharepoint.com/sites/comms" }, undefined, "OnlyPeopleInOrg", new Map());
    expect(site.ownerUPN).toBe("");
    expect(site.storageUsedGB).toBe(0);
  });
});

describe("mapTenantSharingSettings", () => {
  it("maps the sharing capability and link type enums", () => {
    const result = mapTenantSharingSettings({
      sharingCapability: "externalUserAndGuestSharing",
      sharingLinkDefaultType: "anonymousAccess",
      anonymousLinkExpirationRestrictionDays: 0,
    });
    expect(result.tenantSharingLevel).toBe("Anyone");
    expect(result.defaultLinkType).toBe("Anyone");
    expect(result.anonymousLinkExpirationDays).toBe(0);
  });

  it("falls back to sensible defaults for unrecognized values", () => {
    const result = mapTenantSharingSettings({});
    expect(result.tenantSharingLevel).toBe("NewAndExistingGuests");
    expect(result.defaultLinkType).toBe("Internal");
    expect(result.anonymousLinkExpirationDays).toBe(0);
  });
});
