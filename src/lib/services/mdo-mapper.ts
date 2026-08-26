import { MdoThreatPolicy, TablEntry } from "../types";

// Maps raw Exchange Online PowerShell cmdlet output (via the modern EXO V3
// REST "InvokeCommand" surface, see exo-client.ts) into Clarity365's MDO
// policy/TABL shapes. The EXO cmdlet output field names referenced below
// (Enabled, EnableTargetedUserProtection, SpamZapEnabled, etc.) are based on
// the documented Get-*Policy cmdlets as of this writing — worth confirming
// against a real tenant's actual JSON shape during live testing, since EXO's
// PowerShell-oriented serialization can have quirks (e.g. field casing, or a
// single result serializing as an object instead of a one-item array —
// exo-client.ts's invokeExoCommand already normalizes the latter).

function deriveState(raw: any): MdoThreatPolicy["state"] {
  if (raw.Enabled === false || raw.IsEnabled === false) return "Disabled";
  return "Enabled";
}

function deriveAssignedScope(raw: any): string {
  const scopedFields = [raw.RecipientDomainIs, raw.SentTo, raw.SentToMemberOf, raw.RecipientDomainIsInList].filter(
    (v) => Array.isArray(v) && v.length > 0
  );
  if (scopedFields.length === 0) return "Default (Organization-wide)";
  return scopedFields.flat().join(", ");
}

// Each policyType has its own specific baseline-relevant field(s) — the same
// ones mdo-baseline-matcher.ts scores per MDO0x check. Keying compliance off
// exactly those fields (rather than a generic OR across anti-phish-shaped
// booleans) keeps this rating consistent with the Baseline & Posture tab's
// own verdicts for the identical policy. AntiPhishing backs three checks
// (MDO01/02/04) so all three must hold for it to count as compliant.
function deriveComplianceRating(
  policyType: MdoThreatPolicy["policyType"],
  enabled: boolean,
  fields: Pick<
    MdoThreatPolicy,
    "impersonationProtection" | "spoofIntelligence" | "zapEnabled" | "realTimeScanning" | "blockingAction" | "commonAttachmentFilter" | "outboundNotify"
  >
): MdoThreatPolicy["complianceRating"] {
  if (!enabled) return "critical";
  const protectionsActive: Record<MdoThreatPolicy["policyType"], boolean> = {
    AntiPhishing: fields.impersonationProtection && fields.spoofIntelligence && fields.zapEnabled,
    AntiSpamInbound: fields.zapEnabled,
    AntiSpamOutbound: fields.outboundNotify,
    AntiMalware: fields.commonAttachmentFilter,
    SafeLinks: fields.realTimeScanning,
    SafeAttachments: fields.blockingAction,
  };
  return protectionsActive[policyType] ? "compliant" : "substandard";
}

export function mapMdoPolicy(raw: any, policyType: MdoThreatPolicy["policyType"]): MdoThreatPolicy {
  const enabled = raw.Enabled !== false && raw.IsEnabled !== false;
  const impersonationProtection = !!(
    raw.EnableTargetedUserProtection ||
    raw.EnableTargetedDomainsProtection ||
    raw.EnableOrganizationDomainsProtection
  );
  const spoofIntelligence = !!raw.EnableSpoofIntelligence;
  const zapEnabled = !!(raw.SpamZapEnabled || raw.PhishZapEnabled || raw.ZapEnabled);

  // Baseline-scoring fields (see mdo-baseline-definitions.ts) — each backs one
  // specific MDO0x check, so unlike the generic booleans above these are only
  // meaningful for the policyType that actually carries them.
  const realTimeScanning = !!(raw.EnableSafeLinksForEmail && raw.ScanUrls);
  const blockingAction = raw.Action === "Block" || raw.Action === "DynamicDelivery";
  const commonAttachmentFilter = !!raw.EnableFileFilter;
  const outboundNotify = !!raw.NotifyOutboundSpam;
  const autoForwardingBlocked = raw.AutoForwardingMode === "Off";

  return {
    id: raw.Guid || raw.Identity || raw.Name || policyType,
    policyType,
    displayName: raw.Name || raw.Identity || policyType,
    state: deriveState(raw),
    assignedScope: deriveAssignedScope(raw),
    impersonationProtection,
    spoofIntelligence,
    zapEnabled,
    complianceRating: deriveComplianceRating(policyType, enabled, {
      impersonationProtection,
      spoofIntelligence,
      zapEnabled,
      realTimeScanning,
      blockingAction,
      commonAttachmentFilter,
      outboundNotify,
    }),
    realTimeScanning,
    blockingAction,
    commonAttachmentFilter,
    outboundNotify,
    autoForwardingBlocked,
  };
}

// Shared 90-day default used both for the human "Add TABL Entry" form
// (MdoPoliciesModule.tsx) and the MCP manage_tabl tool (mcp/engine.ts), so
// the "not recommended" no-expiration hygiene rule applies consistently
// regardless of who/what created the entry.
export function defaultTablExpirationIso(): string {
  return new Date(Date.now() + 90 * 86_400_000).toISOString();
}

export type TablListType = "Sender" | "Url" | "FileHash";

// Inverse of the entryType derivation in mapTablEntry below — used when
// writing an entry back to EXO (New-/Remove-TenantAllowBlockListItems take a
// -ListType, not Clarity365's finer-grained entryType).
export function mapEntryTypeToListType(entryType: TablEntry["entryType"]): TablListType {
  if (entryType === "url") return "Url";
  if (entryType === "file_hash") return "FileHash";
  return "Sender"; // domain and sender both live under EXO's "Sender" ListType.
}

export function mapTablEntry(raw: any, listType: TablListType): TablEntry {
  const value = raw.Value ?? raw.Entry ?? raw.SenderDomainIs ?? raw.Identity ?? "";
  const entryType: TablEntry["entryType"] =
    listType === "Url" ? "url" : listType === "FileHash" ? "file_hash" : String(value).includes("@") ? "sender" : "domain";

  return {
    id: raw.Identity || raw.EntryId || `${listType}-${value}`,
    listType: raw.Action === "Allow" ? "allow" : "block",
    entryType,
    value: String(value),
    addedBy: raw.SubmissionID || raw.LastModifiedBy || "Exchange Online",
    dateAdded: raw.LastModifiedDateTime || raw.CreatedDateTime || new Date().toISOString(),
    expirationDate: raw.ExpirationDate || "Never",
    notes: raw.Notes || (raw.NoExpiration ? "No expiration configured." : ""),
  };
}
