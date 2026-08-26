import { describe, it, expect } from "vitest";
import { evaluateGroupsBaseline, GroupsBaselineInput } from "./groups-baseline-matcher";
import { GROUPS_BASELINE_STANDARDS } from "../data/groups-baseline-definitions";
import { TenantGroup } from "../types";

function group(overrides: Partial<TenantGroup> & Pick<TenantGroup, "id" | "displayName">): TenantGroup {
  return {
    mailNickname: overrides.id,
    groupType: "Security",
    membershipType: "Assigned",
    ownersCount: 1,
    membersCount: 1,
    owners: ["owner@contoso.com"],
    members: ["member@contoso.com"],
    isPrivileged: false,
    syncSource: "Cloud",
    createdDateTime: new Date().toISOString(),
    isAssignableToRole: false,
    guestMemberCount: 0,
    ...overrides,
  };
}

function baseInput(overrides: Partial<GroupsBaselineInput> = {}): GroupsBaselineInput {
  return {
    groups: [],
    caExclusionGroupIds: new Set(),
    weakMfaUserPrincipalNamesLower: new Set(),
    groupExpirationPolicyEnabled: true,
    groupSelfServiceCreationRestricted: true,
    groupNamingPolicyEnabled: true,
    ...overrides,
  };
}

describe("evaluateGroupsBaseline", () => {
  it("scores 100% when everything is compliant", () => {
    const { results, coveragePercent } = evaluateGroupsBaseline(baseInput());
    expect(coveragePercent).toBe(100);
    expect(results).toHaveLength(GROUPS_BASELINE_STANDARDS.length);
    expect(results.every((r) => r.met)).toBe(true);
  });

  it("G01 flags groups with zero owners", () => {
    const groups = [group({ id: "g1", displayName: "Orphaned Group", ownersCount: 0 })];
    const result = evaluateGroupsBaseline(baseInput({ groups })).results.find((r) => r.code === "G01")!;
    expect(result.met).toBe(false);
    expect(result.offendingGroupNames).toEqual(["Orphaned Group"]);
  });

  it("G02 flags role-assignable groups with guest members", () => {
    const groups = [group({ id: "g2", displayName: "Admins", isAssignableToRole: true, guestMemberCount: 1 })];
    const result = evaluateGroupsBaseline(baseInput({ groups })).results.find((r) => r.code === "G02")!;
    expect(result.met).toBe(false);
  });

  it("G02 does not flag a role-assignable group with no guests", () => {
    const groups = [group({ id: "g2b", displayName: "Admins", isAssignableToRole: true, guestMemberCount: 0 })];
    expect(evaluateGroupsBaseline(baseInput({ groups })).results.find((r) => r.code === "G02")!.met).toBe(true);
  });

  it("G03 flags large CA-exclusion groups but not small ones", () => {
    const smallExclusion = [group({ id: "g3", displayName: "Break Glass", membersCount: 3 })];
    expect(
      evaluateGroupsBaseline(baseInput({ groups: smallExclusion, caExclusionGroupIds: new Set(["g3"]) })).results.find(
        (r) => r.code === "G03"
      )!.met
    ).toBe(true);

    const largeExclusion = [group({ id: "g4", displayName: "Break Glass Grown", membersCount: 40 })];
    const result = evaluateGroupsBaseline(baseInput({ groups: largeExclusion, caExclusionGroupIds: new Set(["g4"]) })).results.find(
      (r) => r.code === "G03"
    )!;
    expect(result.met).toBe(false);
    expect(result.offendingGroupNames).toEqual(["Break Glass Grown"]);
  });

  it("G03 ignores groups not referenced as a CA exclusion, regardless of size", () => {
    const groups = [group({ id: "g5", displayName: "Big Ordinary Group", membersCount: 500 })];
    expect(evaluateGroupsBaseline(baseInput({ groups })).results.find((r) => r.code === "G03")!.met).toBe(true);
  });

  it("G04 flags role-assignable groups whose members lack strong MFA", () => {
    const groups = [
      group({ id: "g6", displayName: "Admins", isAssignableToRole: true, members: ["weak@contoso.com"] }),
    ];
    const result = evaluateGroupsBaseline(
      baseInput({ groups, weakMfaUserPrincipalNamesLower: new Set(["weak@contoso.com"]) })
    ).results.find((r) => r.code === "G04")!;
    expect(result.met).toBe(false);
  });

  it("G04 ignores non-role-assignable groups even with weak-MFA members", () => {
    const groups = [group({ id: "g7", displayName: "Ordinary", isAssignableToRole: false, members: ["weak@contoso.com"] })];
    expect(
      evaluateGroupsBaseline(baseInput({ groups, weakMfaUserPrincipalNamesLower: new Set(["weak@contoso.com"]) })).results.find(
        (r) => r.code === "G04"
      )!.met
    ).toBe(true);
  });

  it("G05/G06/G07 reflect the tenant-wide settings inputs", () => {
    const result = evaluateGroupsBaseline(
      baseInput({ groupExpirationPolicyEnabled: false, groupSelfServiceCreationRestricted: false, groupNamingPolicyEnabled: false })
    ).results;
    expect(result.find((r) => r.code === "G05")!.met).toBe(false);
    expect(result.find((r) => r.code === "G06")!.met).toBe(false);
    expect(result.find((r) => r.code === "G07")!.met).toBe(false);
  });
});
