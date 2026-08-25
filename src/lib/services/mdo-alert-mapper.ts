import { MdoThreatAlert } from "../types";

// Maps a raw Microsoft Graph `alert` (v2) resource (GET /security/alerts_v2,
// filtered to serviceSource 'microsoftDefenderForOffice365') into Clarity365's
// MdoThreatAlert shape. Field names below (severity/status/classification
// enum casing, evidence[].userAccount, alertWebUrl) follow the documented
// Graph Security alerts_v2 schema as of this writing — worth confirming
// against a live tenant, the same honesty caveat used throughout this
// codebase's other external-API mappers (see mdo-mapper.ts's header).

const SEVERITY_MAP: Record<string, MdoThreatAlert["severity"]> = {
  informational: "informational",
  low: "low",
  medium: "medium",
  high: "high",
};

export function normalizeAlertSeverity(raw: string | undefined | null): MdoThreatAlert["severity"] {
  return SEVERITY_MAP[(raw || "").toLowerCase()] || "informational";
}

const STATUS_MAP: Record<string, MdoThreatAlert["status"]> = {
  new: "new",
  inprogress: "inProgress",
  resolved: "resolved",
};

export function normalizeAlertStatus(raw: string | undefined | null): MdoThreatAlert["status"] {
  return STATUS_MAP[(raw || "").toLowerCase()] || "new";
}

const CLASSIFICATION_MAP: Record<string, MdoThreatAlert["classification"]> = {
  truepositive: "truePositive",
  falsepositive: "falsePositive",
  benignpositive: "benignPositive",
};

export function normalizeAlertClassification(raw: string | undefined | null): MdoThreatAlert["classification"] {
  return CLASSIFICATION_MAP[(raw || "").toLowerCase()] || "unknown";
}

// Alert evidence is a heterogeneous array (userEvidence, mailboxEvidence,
// etc.) — only entries that carry a userAccount are relevant to "who was
// affected," and duplicates across multiple evidence entries are collapsed.
export function extractAffectedUsers(evidence: any[] | undefined | null): string[] {
  if (!Array.isArray(evidence)) return [];
  const users = evidence
    .map((e) => e?.userAccount?.userPrincipalName || e?.userAccount?.accountName)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  return Array.from(new Set(users));
}

export function mapMdoAlert(raw: any): MdoThreatAlert {
  return {
    id: raw.id,
    title: raw.title || "Untitled alert",
    severity: normalizeAlertSeverity(raw.severity),
    status: normalizeAlertStatus(raw.status),
    classification: normalizeAlertClassification(raw.classification),
    category: raw.category || "Uncategorized",
    createdDateTime: raw.createdDateTime || new Date().toISOString(),
    description: raw.description || "",
    affectedUsers: extractAffectedUsers(raw.evidence),
    webUrl: raw.alertWebUrl || undefined,
  };
}
