import { ScenarioConfirmation, ScenarioConfirmationKey } from "../types";

// "Confirm once": a handful of Security Scenarios checks rest on settings
// Microsoft doesn't expose to the app at all (or only in tools Clarity365
// can't see, such as Sentinel). Instead of a permanent "manual check", the
// operator confirms the setting once per tenant. The confirmation is stored
// in Clarity365 only (on the tenant record), changes nothing in Microsoft
// 365, and lapses after a year so a stale answer can't stay green forever.

export const SCENARIO_CONFIRMATION_KEYS: ScenarioConfirmationKey[] = ["alert-audit-config", "alert-user-deletion", "sharepoint-anyone-link-expiry", "sharepoint-default-link"];

export const CONFIRMATION_VALID_DAYS = 365;

export function isScenarioConfirmationKey(value: unknown): value is ScenarioConfirmationKey {
  return typeof value === "string" && (SCENARIO_CONFIRMATION_KEYS as string[]).includes(value);
}

export interface ConfirmationState {
  status: ScenarioConfirmation["status"];
  confirmedAt: string;
  note?: string;
  // True once the confirmation is older than CONFIRMATION_VALID_DAYS; it then no longer counts.
  expired: boolean;
  expiresAt: string;
}

export function getConfirmationState(confirmation: ScenarioConfirmation | undefined, now: Date = new Date()): ConfirmationState | undefined {
  if (!confirmation) return undefined;
  const at = Date.parse(confirmation.confirmedAt);
  if (Number.isNaN(at)) return undefined;
  const expiresAt = at + CONFIRMATION_VALID_DAYS * 24 * 60 * 60 * 1000;
  return {
    status: confirmation.status,
    confirmedAt: confirmation.confirmedAt,
    note: confirmation.note,
    expired: now.getTime() >= expiresAt,
    expiresAt: new Date(expiresAt).toISOString(),
  };
}
