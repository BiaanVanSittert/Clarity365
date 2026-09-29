// Pure mapping from one row of a Microsoft Purview unified audit log CSV
// export to a UnifiedAuditLogRecord - isolated from the actual file-reading/
// streaming (done in tenant-store.ts's ingestAuditLogCsv) so the per-record-type
// field-hoisting logic here is independently testable with hand-built fixtures,
// same convention as asr-configuration-mapper.ts and sign-in-country.ts.
//
// Verified export shape (see the plan this module implements): the Purview
// portal's CSV export always has exactly four columns - CreationDate, UserIds,
// Operations, AuditData (a JSON string) - and AuditData's own shape varies by
// RecordType. A PowerShell export (Search-UnifiedAuditLog | Export-Csv) may add
// a fifth RecordType column, but that same value always also lives inside the
// AuditData JSON, so nothing here assumes any column exists except AuditData.
import { UnifiedAuditLogRecord } from "../types";

export interface RawCsvRow {
  [column: string]: string | undefined;
}

export interface ParsedRowContext {
  tenantId: string;
  importId: string;
}

// Microsoft's RecordType enum is numeric in the AuditData JSON itself; a
// PowerShell-exported CSV's standalone RecordType column instead carries the
// friendly string name. This is a deliberately partial map covering the
// workloads this feature's search/templates actually care about (Exchange,
// SharePoint/OneDrive, Entra ID) - an unmapped numeric code is shown as
// "RecordType <n>" rather than silently guessed at.
const RECORD_TYPE_NAMES: Record<number, string> = {
  1: "ExchangeAdmin",
  2: "ExchangeItem",
  3: "ExchangeItemGroup",
  4: "SharePoint",
  6: "SharePointFileOperation",
  7: "OneDrive",
  8: "AzureActiveDirectory",
  9: "AzureActiveDirectoryAccountLogon",
  11: "ComplianceDLPSharePoint",
  13: "ComplianceDLPExchange",
  14: "SharePointSharingOperation",
  15: "AzureActiveDirectoryStsLogon",
  16: "SecurityComplianceCenterEOPCmdlet",
  19: "Yammer",
  21: "Discovery",
  22: "MicrosoftTeams",
  23: "ThreatIntelligence",
  30: "SharePointListOperation",
  38: "ThreatIntelligenceUrl",
  40: "SecurityComplianceAlerts",
};

function normalizeRecordType(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "number") return RECORD_TYPE_NAMES[value] || `RecordType ${value}`;
  const asNumber = Number(value);
  if (!Number.isNaN(asNumber) && String(asNumber) === String(value).trim()) {
    return RECORD_TYPE_NAMES[asNumber] || `RecordType ${asNumber}`;
  }
  return String(value);
}

function firstNonEmpty(...values: (unknown | undefined)[]): string | undefined {
  for (const v of values) {
    if (v === undefined || v === null) continue;
    const s = String(v).trim();
    if (s) return s;
  }
  return undefined;
}

// The CSV's UserIds column has been observed both as a plain UPN string and
// as a JSON array (e.g. from a multi-mailbox search) - handle both rather
// than assuming one.
function extractUserId(userIdsColumn: string | undefined, auditData: Record<string, any>): string | undefined {
  if (userIdsColumn) {
    const trimmed = userIdsColumn.trim();
    if (trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed) && parsed.length > 0) return String(parsed[0]);
      } catch {
        // Fall through to treating it as a plain string below.
      }
    }
    if (trimmed) return trimmed;
  }
  return firstNonEmpty(auditData.UserId, auditData.UserKey);
}

// Exchange mailbox-audit records (e.g. MailItemsAccessed) carry SessionId +
// ClientIPAddress + ClientInfoString - Microsoft's own documented technique
// for telling attacker activity apart from the legitimate user's own activity
// in a compromised mailbox. Entra ID sign-in-flavored records instead use
// ClientIP and don't have a SessionId. Both are checked since which fields
// exist depends entirely on RecordType.
function extractClientIp(auditData: Record<string, any>): string | undefined {
  return firstNonEmpty(auditData.ClientIP, auditData.ClientIPAddress, auditData.ActorIpAddress);
}

function extractClientInfo(auditData: Record<string, any>): string | undefined {
  const direct = firstNonEmpty(auditData.ClientInfoString, auditData.ClientAppId, auditData.UserAgent, auditData.Client);
  if (direct) return direct;
  // Entra ID audit records sometimes carry device/browser info as an
  // ExtendedProperties/DeviceProperties array of {Name, Value} pairs instead
  // of a flat field - not a guaranteed structured DeviceId, but still useful,
  // free-text client-identifying text worth surfacing in search.
  const props: Array<{ Name?: string; Value?: string }> | undefined =
    auditData.DeviceProperties || auditData.ExtendedProperties;
  if (Array.isArray(props)) {
    const displayName = props.find((p) => p?.Name === "DisplayName" || p?.Name === "OS")?.Value;
    if (displayName) return displayName;
  }
  return undefined;
}

export interface MapCsvRowResult {
  record: Omit<UnifiedAuditLogRecord, "id">;
  parseError: boolean;
}

// Maps one papaparse row (header: true, so column-name-keyed) to a record
// ready for insertion. Never throws - a malformed AuditData JSON blob
// degrades to a best-effort record with parseError: true rather than aborting
// the whole import over one bad row.
export function mapCsvRowToRecord(row: RawCsvRow, context: ParsedRowContext): MapCsvRowResult {
  const rawAuditData = row.AuditData;
  let auditData: Record<string, any> = {};
  let parseError = false;

  if (rawAuditData) {
    try {
      auditData = JSON.parse(rawAuditData);
    } catch {
      parseError = true;
    }
  }

  const creationDate =
    firstNonEmpty(row.CreationDate, auditData.CreationTime) || new Date(0).toISOString();
  const recordType = normalizeRecordType(row.RecordType ?? auditData.RecordType);
  const operation = firstNonEmpty(row.Operations, auditData.Operation);
  const userId = extractUserId(row.UserIds, auditData);
  const clientIp = extractClientIp(auditData);
  const sessionId = firstNonEmpty(auditData.SessionId);
  const clientInfo = extractClientInfo(auditData);
  const resultStatus = firstNonEmpty(auditData.ResultStatus, auditData.ResultStatusDetail);
  const workload = firstNonEmpty(auditData.Workload, row.RecordType);

  const rawData = JSON.stringify({
    CreationDate: row.CreationDate,
    UserIds: row.UserIds,
    Operations: row.Operations,
    RecordType: row.RecordType,
    AuditData: parseError ? rawAuditData : auditData,
  });

  return {
    record: {
      tenantId: context.tenantId,
      importId: context.importId,
      creationDate,
      recordType,
      operation,
      userId,
      clientIp,
      sessionId,
      clientInfo,
      resultStatus,
      workload,
      rawData,
      parseError,
    },
    parseError,
  };
}

// Purview's own export size caps - a nudge, not a verdict about which plan
// produced the file. See UnifiedAuditLogImport.possiblyCapped.
const AUDIT_STANDARD_EXPORT_CAP = 50_000;
const AUDIT_PREMIUM_EXPORT_CAP = 1_000_000;

export function getExportCapWarning(rowCount: number): string | undefined {
  if (rowCount >= AUDIT_PREMIUM_EXPORT_CAP) {
    return `This file has ${rowCount.toLocaleString()} rows, at or above Purview Audit (Premium)'s 1,000,000-row export cap - if your real investigation window is wider than what this file covers, export a narrower date range and upload it separately to fill the gap.`;
  }
  if (rowCount >= AUDIT_STANDARD_EXPORT_CAP) {
    return `This file has ${rowCount.toLocaleString()} rows, at or above Purview Audit (Standard)'s 50,000-row export cap - if this tenant is on Audit Standard, the export may have been truncated and your investigation window could be incomplete.`;
  }
  return undefined;
}
