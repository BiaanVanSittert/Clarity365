// Mirrors mailflow-baseline-definitions.ts's pattern for Groups & Distribution:
// named checks, each scored against live group/tenant-setting data by
// groups-baseline-matcher.ts. None of these ship a one-click fix in this
// pass - G01-G04 are inherently judgment calls (who should own a group,
// whether a guest/broad CA-exclusion membership is legitimate), and G05-G07
// (tenant-wide group settings) are real settable values via
// PATCH /groupSettings/{id} but are left as review-only for now rather than
// adding a write path in the same pass as the initial read-side buildout -
// same "no auto-fix" convention already used for MDO09/MF03/MF05/MF06.

export interface GroupsBaselineCheck {
  code: string;
  name: string;
  description: string;
  riskMitigated: string;
}

export const GROUPS_BASELINE_STANDARDS: GroupsBaselineCheck[] = [
  {
    code: "G01",
    name: "No group has zero owners",
    description:
      "Every security group, M365 group, and distribution list has at least one owner who can approve membership changes and answer for why the group exists.",
    riskMitigated:
      "An orphaned group's access rights go unmanaged by default - no one reviews who's in it or removes people who no longer need access.",
  },
  {
    code: "G02",
    name: "Role-assignable groups have no guest members",
    description:
      "No group whose membership directly grants an Entra ID directory role (isAssignableToRole) includes an external guest account.",
    riskMitigated:
      "Membership in a role-assignable group IS an admin role grant - a guest account in one of these groups is effectively an external party holding a directory role.",
  },
  {
    code: "G03",
    name: "Conditional Access exclusion groups stay small",
    description:
      "No group referenced as a Conditional Access policy exclusion (a 'break-glass' or bypass group) has grown beyond a handful of members.",
    riskMitigated:
      "A CA-bypass group that quietly grows over time is one of the most common ways a tenant's CA baseline stops meaning anything in practice.",
  },
  {
    code: "G04",
    name: "Role-assignable group members have strong MFA",
    description:
      "Every member of a role-assignable group is registered for MFA and isn't relying on a weak method (SMS/voice/email OTP).",
    riskMitigated:
      "A role-assignable group member without strong MFA is a bigger single point of failure than an ordinary user without it - compromising their credentials is equivalent to compromising the directory role.",
  },
  {
    code: "G05",
    name: "Tenant-wide group expiration policy is configured",
    description: "A Microsoft 365 group expiration/renewal policy exists at the tenant level.",
    riskMitigated:
      "Without one, groups (and the Teams/SharePoint sites behind them) accumulate forever as unreviewed collaboration surfaces.",
  },
  {
    code: "G06",
    name: "Self-service group creation is restricted",
    description: "Group creation is limited to an approved set of requesters rather than open to every user.",
    riskMitigated: "Unrestricted self-service creation leads to ungoverned sprawl - no naming convention, no owner requirement, no review.",
  },
  {
    code: "G07",
    name: "Group naming policy is configured",
    description: "A tenant-wide naming policy (prefix/suffix requirement) is configured for new groups.",
    riskMitigated:
      "Without one, nothing stops a group being named to impersonate a trusted internal function (e.g. \"IT-Support\") to social-engineer its members.",
  },
];
