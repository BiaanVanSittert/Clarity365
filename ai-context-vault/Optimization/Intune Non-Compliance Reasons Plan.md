---
tags: [optimization, plan, intune]
---

# Intune Non-Compliance Reasons - Plan

Status: **shipped** (built 2026-09-22, same day as this plan). User request: clicking the "Non-Compliant Endpoints" square in [[Intune Endpoint Security]] should filter the device table to only non-compliant devices, and each non-compliant device should show *why* it's non-compliant (missing BitLocker, missing Defender Antimalware, below minimum OS version, minimum password length not met, TPM not enabled, etc.). Full build detail (including a staleness bug caught before shipping) is in [[Intune Endpoint Security]]'s 2026-09-22 entry - this document is kept as the original investigation/design record.

## Investigation findings

**Current state (`IntuneSecurityModule.tsx`):** the "Non-Compliant Endpoints" card is a static KPI, not clickable. `IntuneDevice.complianceState` (`compliant`/`noncompliant`/`conflict`/`error`/`inGracePeriod`) is the only compliance signal on the type - there's no per-setting reason anywhere in the data model, mapper, or Graph fetch. Compliant/non-compliant is currently a pass/fail summary with no "why."

**Graph mechanism confirmed live (Microsoft Learn, not assumed):** Microsoft Graph has a real, **v1.0** (not beta), **not deprecated** (docs page last updated 2025-12-03) resource pair built exactly for this:

1. `GET /deviceManagement/deviceCompliancePolicySettingStateSummaries` - a small, tenant-wide list (one row per distinct compliance *setting* actually checked by any assigned compliance policy - e.g. "Require BitLocker," "Require Threat scan," "Minimum OS version" - realistically single digits to ~20 rows, not per-device). Each row: `id`, `setting`, `settingName`, `platformType`, plus aggregate counts (`compliantDeviceCount`, `nonCompliantDeviceCount`, `errorDeviceCount`, `conflictDeviceCount`, etc.).
2. `GET /deviceManagement/deviceCompliancePolicySettingStateSummaries/{id}/deviceComplianceSettingStates` - the per-device breakdown for *that one setting*: `deviceId`, `deviceName`, `userPrincipalName`, `setting`, `settingName`, `state` (`compliant`/`nonCompliant`/`remediated`/`error`/`conflict`/`notApplicable`/`unknown`), `complianceGracePeriodExpirationDateTime`.

This is the right mechanism because it's **fleet-wide, not per-device** - a small, bounded number of calls (one per distinct setting, not one per device), the same shape of tradeoff already made for MDE onboarding status (`atpOnboardingStates` in `graph-client.ts`) rather than the expensive per-device `managedDevices/{id}/deviceCompliancePolicyStates` drill-down. **Confirmed no new permission grant needed** - both endpoints require `DeviceManagementConfiguration.Read.All`, which this app already requests (used by the Endpoint Security / ASR modules today).

**Unconfirmed, to verify live before calling this done:** whether `$expand=deviceComplianceSettingStates` on the top-level list call returns everything in one round-trip (cheaper) or whether each summary's child collection must be fetched with its own follow-up call (still cheap - bounded by distinct-setting count, just N calls instead of 1). Plan for the fallback (N calls) as the baseline, try `$expand` first and keep whichever actually works once tested against a real tenant with assigned compliance policies and real non-compliant devices.

**Real-world caveat to set expectations on, not a code gap:** the specific reasons available depend entirely on what that client's own Intune compliance policies check. A tenant with a minimal compliance policy (just "mark noncompliant after grace period," no specific settings) will show sparse or no reasons even for a genuinely non-compliant device - this reflects Microsoft's own compliance model, not a Clarity365 gap. Worth a UI fallback message ("No specific setting failures reported by Microsoft for this device - check the compliance policy's own configuration") rather than an empty-looking blank.

## Proposed data model (`src/lib/types/index.ts`)

```ts
export interface DeviceComplianceReason {
  settingName: string;   // Graph's own human-readable name, e.g. "Require BitLocker"
  state: "nonCompliant" | "error" | "conflict" | "unknown";
}
```

Add to `IntuneDevice`:
```ts
// Per-setting reasons this device is failing compliance - only populated
// for devices with at least one non-compliant/error/conflict setting.
// Sourced from deviceCompliancePolicySettingStateSummaries (see
// ai-context-vault/Optimization/Intune Non-Compliance Reasons Plan.md).
nonComplianceReasons?: DeviceComplianceReason[];
```
Optional field, additive-only - no backfill/migration concern for old persisted snapshots (same `withLegacyDefaults()`-free treatment as any other genuinely-optional field; `undefined` just means "not yet re-synced," handled the same as a device with zero reasons).

## Proposed Graph fetch (`graph-client.ts`)

New sync step, same resilience pattern as every other step (try/catch, pushes to `syncErrors`, never blocks the rest of the sync on failure):

1. Fetch `deviceCompliancePolicySettingStateSummaries` (try `$expand=deviceComplianceSettingStates` first; fall back to per-summary follow-up calls if the expand comes back empty/unsupported).
2. Filter each device row to `state` in `{"nonCompliant", "error", "conflict"}` (skip `compliant`/`remediated`/`notApplicable`/`unknown`).
3. Group into `Map<deviceName, DeviceComplianceReason[]>` - **match by `deviceName`, not `deviceId`**, mirroring the exact same deliberate choice already made for `applyRealEdrOnboardingStates` (that function's own comment/precedent suggests `deviceId` on this class of Graph resource hasn't reliably lined up with `managedDevices`' own `id` in this codebase's prior experience - re-verify live whether that's still true here rather than assuming, but default to the proven-safe match key).
4. New pure, tested function in `intune-mapper.ts`: `applyDeviceComplianceReasons(devices, reasonsByDeviceName)` - same shape/spirit as `applyRealEdrOnboardingStates`.
5. New `onProgress` step (`TOTAL_SYNC_STEPS` +1).

## Proposed UI (`IntuneSecurityModule.tsx`)

1. **Click-to-filter KPI cards** - `complianceFilter: "all" | "compliant" | "noncompliant"` state, wired onto the existing "Compliant Endpoints" and "Non-Compliant Endpoints" cards, using the **exact established convention** from the 2026-09-11 Sign-In Logs click-to-filter cards (`SignInLogsModule.tsx`): `role="button"`, `tabIndex={0}`, `onKeyDown` for Enter/Space, click-again-to-clear back to `"all"`, active-state border/background change, a `title` tooltip, and a "(Click to filter)" hint appended to the card's existing subtitle. `filteredDevices` gains a `complianceFilter` branch alongside the existing search/OS filters.
2. **Table row - quick-scan reason hint.** For a non-compliant row, add a small subtitle under the existing Compliance `StatusPill` showing the first reason plus a "+N more" count when there's more than one (full list in a `title` tooltip) - keeps the table dense rather than expanding row height per device.
3. **Device drawer - full reasons.** In the existing "Compliance & Security" card (top of the drawer, where the 4-pill grid already lives), add a "Non-Compliant Reasons" block listing each `DeviceComplianceReason.settingName` as its own small red chip/row when `nonComplianceReasons` is non-empty; the "no specific reasons reported" fallback message described above when the device is non-compliant but the array is empty/undefined.
4. **CSV export.** Add a `NonComplianceReasons` column (semicolon-joined setting names) to `handleExportCSV` - cheap, keeps the export as complete as the UI.

## Proposed mock data (`mock-tenants.ts`)

Attach representative `nonComplianceReasons` to a handful of existing non-compliant mock devices across demo tenants, covering the exact examples the user named - "Require BitLocker," "Microsoft Defender Antimalware," "Minimum OS version," "Minimum password length," "Require TPM" - so demo tenants show real variety rather than an empty array everywhere (the same "mock data shouldn't look more/less finished than live data" discipline flagged as a recurring bug class in [[Optimization Plan]]).

## Testing

- `intune-mapper.test.ts`: new tests for `applyDeviceComplianceReasons` - groups correctly by device name (case-insensitive), ignores `compliant`/`remediated`/`notApplicable`/`unknown` states, handles a device with zero matching rows (returns device unchanged, no `nonComplianceReasons` key added), handles multiple reasons for one device.
- No new UI/component tests planned beyond what's already thin coverage for this module (matches the existing convention - see [[Optimization Plan]] item 6 on UI test coverage generally).

## Sequencing

Straightforward, single-pass build (not multi-stage like DLP) - data model → Graph fetch → mapper → UI → mock data → vault doc update → live verification against a real tenant with genuine non-compliant devices (Axiomatic Consultants has real non-compliant devices per the 2026-09-22 Secure Score work) before calling it done, per this project's live-verification discipline.

Part of [[Intune Endpoint Security]] and [[Optimization Plan]].
