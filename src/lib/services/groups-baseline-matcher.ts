import { TenantGroup, GroupsBaselineResult } from "../types";
import { GROUPS_BASELINE_STANDARDS } from "../data/groups-baseline-definitions";
import { computeBaselineCoveragePercent } from "./ca-baseline-matcher";

// A CA-exclusion ("break-glass"/bypass) group beyond this size is flagged for
// review by G03 - a handful of named break-glass accounts is normal and
// expected; dozens of members in an exclusion group usually means it quietly
// became a general-purpose CA bypass over time.
const CA_EXCLUSION_GROUP_MAX_MEMBERS = 5;

export interface GroupsBaselineInput {
  groups: TenantGroup[];
  // Union of every CA policy's conditions.users.excludeGroupIds, across all
  // policies (see types/index.ts's CAPolicyRule.conditions.users.excludeGroupIds).
  caExclusionGroupIds: Set<string>;
  // Lowercased UPNs of users with isWeakAuth || !mfaRegistered (Module 4's
  // mfaAudit) - used by G04 to cross-check role-assignable group members.
  weakMfaUserPrincipalNamesLower: Set<string>;
  groupExpirationPolicyEnabled?: boolean;
  groupSelfServiceCreationRestricted?: boolean;
  groupNamingPolicyEnabled?: boolean;
}

function evaluateCode(code: string, input: GroupsBaselineInput): GroupsBaselineResult {
  if (code === "G01") {
    const offenders = input.groups.filter((g) => g.ownersCount === 0);
    return {
      code,
      met: offenders.length === 0,
      offendingGroupNames: offenders.length > 0 ? offenders.map((g) => g.displayName) : undefined,
    };
  }
  if (code === "G02") {
    const offenders = input.groups.filter((g) => g.isAssignableToRole && g.guestMemberCount > 0);
    return {
      code,
      met: offenders.length === 0,
      offendingGroupNames: offenders.length > 0 ? offenders.map((g) => g.displayName) : undefined,
    };
  }
  if (code === "G03") {
    const offenders = input.groups.filter((g) => input.caExclusionGroupIds.has(g.id) && g.membersCount > CA_EXCLUSION_GROUP_MAX_MEMBERS);
    return {
      code,
      met: offenders.length === 0,
      offendingGroupNames: offenders.length > 0 ? offenders.map((g) => g.displayName) : undefined,
    };
  }
  if (code === "G04") {
    const offenders = input.groups.filter(
      (g) => g.isAssignableToRole && g.members.some((upn) => input.weakMfaUserPrincipalNamesLower.has(upn.toLowerCase()))
    );
    return {
      code,
      met: offenders.length === 0,
      offendingGroupNames: offenders.length > 0 ? offenders.map((g) => g.displayName) : undefined,
    };
  }
  if (code === "G05") return { code, met: input.groupExpirationPolicyEnabled === true };
  if (code === "G06") return { code, met: input.groupSelfServiceCreationRestricted === true };
  if (code === "G07") return { code, met: input.groupNamingPolicyEnabled === true };
  return { code, met: false };
}

export function evaluateGroupsBaseline(input: GroupsBaselineInput): {
  results: GroupsBaselineResult[];
  coveragePercent: number;
} {
  const results = GROUPS_BASELINE_STANDARDS.map((standard) => evaluateCode(standard.code, input));
  const metCount = results.filter((r) => r.met).length;
  return { results, coveragePercent: computeBaselineCoveragePercent(metCount, GROUPS_BASELINE_STANDARDS.length) };
}
