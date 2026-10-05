import { AlertPolicyInventory, AlertPolicySummary } from "../types";

// Microsoft 365 alert policies (Defender portal > Policies & rules > Alert
// policy), as returned by Security & Compliance PowerShell's
// Get-ProtectionAlert (see scc-client.ts). Pure: mapping and "is there an
// alert for this activity" matching, used by security-scenarios.ts.
//
// A policy's `Operation` is the audit-log activity it watches (Microsoft
// Learn, New-ProtectionAlert: "the activities that are monitored ... see
// Audited activities"). Matching is on that field only - never on the
// policy's name, which anyone can type.

export function mapAlertPolicy(raw: any): AlertPolicySummary {
  const list = (value: unknown): string[] => (Array.isArray(value) ? value : value ? [value] : []).filter((v): v is string => typeof v === "string" && v.trim() !== "");
  return {
    name: typeof raw?.Name === "string" ? raw.Name : "Unnamed alert policy",
    operations: list(raw?.Operation),
    disabled: raw?.Disabled === true,
    isSystemRule: raw?.IsSystemRule === true,
    // Only the count: who is notified isn't needed and isn't stored.
    notifyRecipients: list(raw?.NotifyUser).length,
    notificationEnabled: typeof raw?.NotificationEnabled === "boolean" ? raw.NotificationEnabled : undefined,
    aggregation: typeof raw?.AggregationType === "string" ? raw.AggregationType : undefined,
    threshold: typeof raw?.Threshold === "number" ? raw.Threshold : undefined,
    timeWindowMinutes: typeof raw?.TimeWindow === "number" ? raw.TimeWindow : undefined,
    severity: typeof raw?.Severity === "string" ? raw.Severity : undefined,
    category: typeof raw?.Category === "string" ? raw.Category : undefined,
  };
}

// Audit-log activity names. Entra's are written with a trailing full stop in
// the audit log ("Delete user."), so comparison ignores case, surrounding
// space and trailing full stops.
// Set-AdminAuditLogConfig is the cmdlet that turns unified audit logging on
// or off. Set-OrganizationConfig is deliberately not accepted: it changes
// many unrelated settings, so an alert on it says little about auditing.
export const AUDIT_CONFIG_OPERATIONS = ["Set-AdminAuditLogConfig"];
export const USER_DELETION_OPERATIONS = ["Delete user"];

const normalize = (operation: string) => operation.trim().toLowerCase().replace(/\.+$/, "");

export type AlertCoverageState =
  // An enabled policy watches the activity and emails at least one person.
  | "alerting"
  // An enabled policy watches it, but nobody is emailed (the alert only shows in the portal).
  | "raisedNotEmailed"
  // The only matching policies are turned off.
  | "disabledOnly"
  // Alert policies were read and none watches the activity.
  | "none"
  // Alert policies couldn't be read (not synced, not set up, or an error).
  | "unknown";

export interface AlertCoverage {
  state: AlertCoverageState;
  // The policies behind the state (matching ones; empty for "none"/"unknown").
  policies: AlertPolicySummary[];
}

const emailsSomeone = (p: AlertPolicySummary) => p.notifyRecipients > 0 && p.notificationEnabled !== false;

export function findAlertCoverage(inventory: AlertPolicyInventory | undefined, operations: string[]): AlertCoverage {
  if (!inventory || inventory.unavailable) return { state: "unknown", policies: [] };
  const wanted = new Set(operations.map(normalize));
  const matching = inventory.policies.filter((p) => p.operations.some((op) => wanted.has(normalize(op))));
  const enabled = matching.filter((p) => !p.disabled);
  const alerting = enabled.filter(emailsSomeone);
  if (alerting.length > 0) return { state: "alerting", policies: alerting };
  if (enabled.length > 0) return { state: "raisedNotEmailed", policies: enabled };
  if (matching.length > 0) return { state: "disabledOnly", policies: matching };
  return { state: "none", policies: [] };
}

// "more than 5 in 60 minutes" for an aggregated policy, "" for a per-event one.
export function describeAlertTrigger(policy: AlertPolicySummary): string {
  if (policy.aggregation === "SimpleAggregation" && policy.threshold) {
    return `more than ${policy.threshold} in ${policy.timeWindowMinutes ?? "?"} minutes`;
  }
  if (policy.aggregation === "AnomalousAggregation") return "unusual volume";
  return "";
}
