import { describe, it, expect } from "vitest";
import {
  mapGroupType,
  mapMembershipType,
  mapGroup,
  mapGroupExpirationPolicyEnabled,
  mapGroupSelfServiceCreationRestricted,
  mapGroupNamingPolicyEnabled,
} from "./groups-mapper";

describe("mapGroupType", () => {
  it("maps M365Unified from the Unified groupType", () => {
    expect(mapGroupType({ groupTypes: ["Unified"] })).toBe("M365Unified");
  });

  it("maps MailEnabledSecurity when both mail-enabled and security-enabled", () => {
    expect(mapGroupType({ mailEnabled: true, securityEnabled: true })).toBe("MailEnabledSecurity");
  });

  it("maps DistributionList when mail-enabled but not security-enabled", () => {
    expect(mapGroupType({ mailEnabled: true, securityEnabled: false })).toBe("DistributionList");
  });

  it("defaults to Security otherwise", () => {
    expect(mapGroupType({ mailEnabled: false, securityEnabled: true })).toBe("Security");
  });
});

describe("mapMembershipType", () => {
  it("maps Dynamic from the DynamicMembership groupType", () => {
    expect(mapMembershipType({ groupTypes: ["DynamicMembership"] })).toBe("Dynamic");
  });

  it("defaults to Assigned", () => {
    expect(mapMembershipType({ groupTypes: [] })).toBe("Assigned");
  });
});

describe("mapGroup", () => {
  it("maps a role-assignable security group with no guests", () => {
    const group = mapGroup(
      { id: "g1", displayName: "SecOps", isAssignableToRole: true, createdDateTime: "2024-01-01T00:00:00Z" },
      ["admin@contoso.com"],
      [{ userPrincipalName: "admin@contoso.com", userType: "Member" }]
    );
    expect(group.isAssignableToRole).toBe(true);
    expect(group.isPrivileged).toBe(true);
    expect(group.guestMemberCount).toBe(0);
    expect(group.ownersCount).toBe(1);
    expect(group.membersCount).toBe(1);
  });

  it("counts guest members from the member sample", () => {
    const group = mapGroup(
      { id: "g2", displayName: "Research Collab" },
      [],
      [
        { userPrincipalName: "internal@contoso.com", userType: "Member" },
        { userPrincipalName: "external#EXT#@contoso.com", userType: "Guest" },
      ]
    );
    expect(group.guestMemberCount).toBe(1);
  });

  it("maps onPremisesSyncEnabled to WindowsServerAD sync source", () => {
    expect(mapGroup({ id: "g3", onPremisesSyncEnabled: true }, [], []).syncSource).toBe("WindowsServerAD");
    expect(mapGroup({ id: "g4" }, [], []).syncSource).toBe("Cloud");
  });

  it("carries the dynamic membership rule text through when present", () => {
    const group = mapGroup({ id: "g5", membershipRule: '(user.department -eq "Finance")' }, [], []);
    expect(group.membershipRule).toBe('(user.department -eq "Finance")');
  });
});

describe("group tenant-settings mappers", () => {
  const settingsWithLifetime = [
    { displayName: "Group.Unified", values: [{ name: "GroupLifetimeInDays", value: "365" }, { name: "EnableGroupCreation", value: "false" }, { name: "PrefixSuffixNamingRequirement", value: "GRP_[GroupName]" }] },
  ];
  const settingsBlank: any[] = [];

  it("reports expiration policy enabled only when a real lifetime is set", () => {
    expect(mapGroupExpirationPolicyEnabled(settingsWithLifetime)).toBe(true);
    expect(mapGroupExpirationPolicyEnabled(settingsBlank)).toBe(false);
  });

  it("reports self-service creation restricted only when explicitly false", () => {
    expect(mapGroupSelfServiceCreationRestricted(settingsWithLifetime)).toBe(true);
    expect(mapGroupSelfServiceCreationRestricted(settingsBlank)).toBe(false);
  });

  it("reports naming policy enabled only when a non-empty pattern is set", () => {
    expect(mapGroupNamingPolicyEnabled(settingsWithLifetime)).toBe(true);
    expect(mapGroupNamingPolicyEnabled(settingsBlank)).toBe(false);
  });
});
