import { SharePointSiteItem, SharePointTenantPolicy, TenantGroup } from "../types";

// Maps raw Microsoft Graph `site`/`drive` resources and the tenant-wide
// SharePoint admin settings resource into Clarity365's SharePoint types.
// Field names are based on the documented Graph resources as of this
// writing - worth confirming against a live tenant, same honesty caveat as
// this codebase's other external-API mappers (see mdo-mapper.ts's header).
//
// Two things are deliberately approximate rather than fabricated precision:
// per-site sharingCapability (defaults to the tenant-wide ceiling - Graph
// doesn't expose a reliable per-site override outside the SharePoint
// Admin/PnP surface this app doesn't have a credential for) and
// isSensitiveDataPresent (a keyword heuristic, not a real Purview
// sensitivity-label/DLP signal). Hub-site detection is not attempted in this
// pass - sites are inferred as TeamSite/CommunicationSite/PersonalOneDrive
// only.

const SENSITIVE_KEYWORDS = [
  "finance",
  "financ",
  "payroll",
  "hr",
  "human resources",
  "legal",
  "clinical",
  "patient",
  "phi",
  "hipaa",
  "confidential",
  "executive",
  "board",
  "m&a",
  "merger",
  "salary",
  "compensation",
];

export function detectSensitiveDataHeuristic(siteName: string, siteUrl: string): boolean {
  const haystack = `${siteName} ${siteUrl}`.toLowerCase();
  return SENSITIVE_KEYWORDS.some((kw) => haystack.includes(kw));
}

export function inferSiteTemplate(raw: any): SharePointSiteItem["template"] {
  const webUrl: string = raw.webUrl || "";
  if (/-my\.sharepoint\.com\/personal\//i.test(webUrl)) return "PersonalOneDrive";
  if (raw.sharepointIds?.groupId) return "TeamSite";
  return "CommunicationSite";
}

// Bytes → whole-number GB, matching the rounding style already used for
// mailbox storage (see mailflow-mapper.ts's parseExchangeSizeToMB).
function bytesToGB(bytes: number | undefined | null): number {
  if (!bytes) return 0;
  return Math.round((bytes / (1024 * 1024 * 1024)) * 10) / 10;
}

export function mapSharePointSite(
  raw: any,
  driveQuota: { used?: number; total?: number } | undefined,
  tenantSharingLevel: SharePointTenantPolicy["tenantSharingLevel"],
  groupsById: Map<string, TenantGroup>
): SharePointSiteItem {
  const siteName: string = raw.displayName || raw.name || "Unnamed site";
  const siteUrl: string = raw.webUrl || "";
  const groupId: string | undefined = raw.sharepointIds?.groupId;
  const ownerUPN = (groupId && groupsById.get(groupId)?.owners[0]) || "";

  return {
    id: raw.id,
    siteName,
    siteUrl,
    template: inferSiteTemplate(raw),
    storageUsedGB: bytesToGB(driveQuota?.used),
    storageAllocatedGB: bytesToGB(driveQuota?.total),
    sharingCapability: tenantSharingLevel,
    isSensitiveDataPresent: detectSensitiveDataHeuristic(siteName, siteUrl),
    ownerUPN,
    lastActivityDate: raw.lastModifiedDateTime || raw.createdDateTime || new Date().toISOString(),
  };
}

// GET /v1.0/admin/sharepoint/settings - tenant-wide SharePoint admin
// settings. This is a comparatively new Graph resource; field names here are
// a best-effort mapping and most worth confirming against a live tenant of
// everything in this file.
export function mapTenantSharingSettings(raw: any): Pick<SharePointTenantPolicy, "tenantSharingLevel" | "defaultLinkType" | "anonymousLinkExpirationDays"> {
  const capabilityMap: Record<string, SharePointTenantPolicy["tenantSharingLevel"]> = {
    externalUserAndGuestSharing: "Anyone",
    externalUserSharingOnly: "NewAndExistingGuests",
    existingExternalUserSharingOnly: "ExistingGuests",
    disabled: "OnlyPeopleInOrg",
  };
  const linkTypeMap: Record<string, SharePointTenantPolicy["defaultLinkType"]> = {
    direct: "SpecificPeople",
    internal: "Internal",
    anonymousAccess: "Anyone",
  };

  return {
    tenantSharingLevel: capabilityMap[raw.sharingCapability] || "NewAndExistingGuests",
    defaultLinkType: linkTypeMap[raw.sharingLinkDefaultType] || "Internal",
    anonymousLinkExpirationDays: typeof raw.anonymousLinkExpirationRestrictionDays === "number" ? raw.anonymousLinkExpirationRestrictionDays : 0,
  };
}
