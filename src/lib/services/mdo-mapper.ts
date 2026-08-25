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

function deriveComplianceRating(enabled: boolean, protectionsActive: boolean): MdoThreatPolicy["complianceRating"] {
  if (!enabled) return "critical";
  return protectionsActive ? "compliant" : "substandard";
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
  // Safe Links/Attachments don't have the anti-phish-specific flags above, but
  // simply having the policy configured at all is itself the protection.
  const protectionsActive =
    impersonationProtection || spoofIntelligence || zapEnabled || policyType === "SafeLinks" || policyType === "SafeAttachments";

  return {
    id: raw.Guid || raw.Identity || raw.Name || policyType,
    policyType,
    displayName: raw.Name || raw.Identity || policyType,
    state: deriveState(raw),
    assignedScope: deriveAssignedScope(raw),
    impersonationProtection,
    spoofIntelligence,
    zapEnabled,
    complianceRating: deriveComplianceRating(enabled, protectionsActive),
  };
}

export type TablListType = "Sender" | "Url" | "FileHash";

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
