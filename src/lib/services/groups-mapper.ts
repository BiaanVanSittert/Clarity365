import { TenantGroup } from "../types";

// Maps raw Microsoft Graph `group` resources (GET /v1.0/groups) into
// Clarity365's TenantGroup shape. Field names below are based on the
// documented Graph group resource as of this writing — worth confirming
// against a live tenant's actual JSON shape during real testing, the same
// honesty caveat used throughout this codebase's other external-API mappers
// (see mdo-mapper.ts's header).
//
// membersCount/guestMemberCount are derived from a capped member-list fetch
// (see graph-client.ts) rather than an exact server-side count, to avoid a
// second per-group round trip just for a number — large groups (>100
// members) will show a lower-bound count, not the true total.

export function mapGroupType(raw: any): TenantGroup["groupType"] {
  const isUnified = Array.isArray(raw.groupTypes) && raw.groupTypes.includes("Unified");
  if (isUnified) return "M365Unified";
  if (raw.mailEnabled && raw.securityEnabled) return "MailEnabledSecurity";
  if (raw.mailEnabled && !raw.securityEnabled) return "DistributionList";
  return "Security";
}

export function mapMembershipType(raw: any): TenantGroup["membershipType"] {
  return Array.isArray(raw.groupTypes) && raw.groupTypes.includes("DynamicMembership") ? "Dynamic" : "Assigned";
}

export function mapGroup(
  raw: any,
  ownerNames: string[],
  memberSample: { userPrincipalName?: string; userType?: string }[]
): TenantGroup {
  const guestMemberCount = memberSample.filter((m) => m.userType === "Guest").length;
  return {
    id: raw.id,
    displayName: raw.displayName || "Unnamed group",
    mailNickname: raw.mailNickname || "",
    groupType: mapGroupType(raw),
    membershipType: mapMembershipType(raw),
    ownersCount: ownerNames.length,
    membersCount: memberSample.length,
    owners: ownerNames,
    members: memberSample.map((m) => m.userPrincipalName || "").filter(Boolean),
    // isAssignableToRole is the precise Graph signal; isPrivileged mirrors it
    // for live data (mock fixtures used isPrivileged as a hand-set flag
    // before this field existed — see mock-tenants.ts).
    isPrivileged: !!raw.isAssignableToRole,
    isAssignableToRole: !!raw.isAssignableToRole,
    syncSource: raw.onPremisesSyncEnabled ? "WindowsServerAD" : "Cloud",
    createdDateTime: raw.createdDateTime || new Date().toISOString(),
    membershipRule: raw.membershipRule || undefined,
    guestMemberCount,
  };
}

// GET /groupSettings — tenant-wide Entra ID group settings (expiration,
// self-service creation, naming policy). Returns a `value` array of
// directorySetting objects, each with a `values` array of {name, value}
// pairs keyed to that setting template's definitions — worth confirming the
// exact template/value names against a live tenant.
export function mapGroupExpirationPolicyEnabled(settingsValue: any[]): boolean {
  const groupSetting = settingsValue.find((s) => s.displayName === "Group.Unified");
  // Presence of a lifetime-days value (not the sentinel "0"/unset) is the
  // clearest signal an expiration policy is actually configured.
  const lifetime = groupSetting?.values?.find((v: any) => v.name === "GroupLifetimeInDays");
  return !!lifetime?.value && lifetime.value !== "0";
}

export function mapGroupSelfServiceCreationRestricted(settingsValue: any[]): boolean {
  const groupSetting = settingsValue.find((s) => s.displayName === "Group.Unified");
  const entry = groupSetting?.values?.find((v: any) => v.name === "EnableGroupCreation");
  // EnableGroupCreation: "true" means ANYONE can create groups — restricted
  // means this is explicitly "false".
  return entry?.value === "false";
}

export function mapGroupNamingPolicyEnabled(settingsValue: any[]): boolean {
  const groupSetting = settingsValue.find((s) => s.displayName === "Group.Unified");
  const prefixSuffix = groupSetting?.values?.find((v: any) => v.name === "PrefixSuffixNamingRequirement");
  return !!prefixSuffix?.value && prefixSuffix.value.trim().length > 0;
}
