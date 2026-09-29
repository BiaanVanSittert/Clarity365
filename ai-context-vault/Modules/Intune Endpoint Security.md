---
tags: [module]
---

# Intune Endpoint Security

Fleet antivirus/EDR onboarding status per device, Windows/macOS/Linux.

- **Component:** `IntuneSecurityModule.tsx`
- **Reads:** `TenantSecuritySnapshot.intune` (prop-driven)
- **Key types:** `IntuneDevice`, `IntunePolicySummary` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Drawer`, `EmptyStateRow`
- **Data origin:** [[Data Mappers]] (`intune-mapper`)

**`edrOnboardingState` is no longer purely an approximation.** `intune-mapper.ts`'s own comment used to (correctly, at the time) disclose that `antivirusStatus`/`edrOnboardingState` weren't real Defender telemetry - both were derived from `complianceState` as a documented proxy, since real per-device MDE onboarding data would need "an extra Graph beta call ... or Microsoft Defender for Endpoint's separate API." That call now exists: `fetchLiveTenantSnapshot` fetches `deviceManagement/advancedThreatProtectionOnboardingStateSummary/advancedThreatProtectionOnboardingDeviceSettingStates` (beta) and `applyRealEdrOnboardingStates()` overrides the compliance-derived guess with the real state wherever a device name match exists (Graph's per-device onboarding record doesn't carry an Intune managedDevice id, so the join is by device name). A device with no match keeps the old approximation rather than looking worse than before this existed. `antivirusStatus` is still the compliance-derived proxy - `windowsProtectionState` (the real per-device AV telemetry) wasn't in scope for this pass, noted here as the natural next fast-follow if this class of gap needs closing again.

## 2026-09-22: click-to-filter Compliant/Non-Compliant KPI cards + per-device non-compliance reasons

User request: clicking the Non-Compliant Endpoints square should filter the device table, and each non-compliant device should show *why* (missing BitLocker, Defender Antimalware missing, below minimum OS version, minimum password length not met, TPM not enabled, etc). Full investigation/design written up first as [[Intune Non-Compliance Reasons Plan]] before building, per this project's own convention for anything touching a Graph fetch shape.

**Graph mechanism** (v1.0, confirmed not deprecated, not beta): `deviceCompliancePolicySettingStateSummaries` - a fleet-wide, not per-device, resource. One row per distinct setting actually checked by an assigned compliance policy (e.g. "Require BitLocker," "Require Threat scan"), each exposing its own nested `deviceComplianceSettingStates` collection listing exactly which devices fail it. Same class of tradeoff already made for `advancedThreatProtectionOnboardingDeviceSettingStates` above - small, bounded number of calls (one per distinct setting, realistically single digits to ~20), not an expensive per-device drill-down via `managedDevices/{id}/deviceCompliancePolicyStates`. Uses `DeviceManagementConfiguration.Read.All`, already required elsewhere in this app - no new permission grant needed.

**New type:** `DeviceComplianceReason { settingName, state: "nonCompliant"|"error"|"conflict" }`, added as an optional `IntuneDevice.nonComplianceReasons[]`. `"unknown"/"compliant"/"remediated"/"notApplicable"` rows are deliberately never turned into a reason - not an actionable finding, so a device with only those has zero reasons, not a confusing "unknown" chip.

**New mapper functions** (`intune-mapper.ts`, tested): `mapDeviceComplianceSettingStateRow()` (per-row raw→typed, returns `null` for non-actionable states) and `applyDeviceComplianceReasons()` (groups by device name, case-insensitive - same join key already used by `applyRealEdrOnboardingStates`, since this Graph resource doesn't carry an Intune managedDevice id either). Wired into `fetchLiveTenantSnapshot` as sync step 20/20 (`TOTAL_SYNC_STEPS` bumped 19→20), same try/catch-and-push-to-syncErrors resilience as every other step - a failure here can't block the rest of the sync.

**UI (`IntuneSecurityModule.tsx`):** the Compliant/Non-Compliant KPI cards are now click-to-filter toggles, using the exact convention already shipped for Sign-In Logs (2026-09-11) - click-again-to-clear, keyboard accessible, active-state border/background, a clearable filter-pill next to the search box. Non-compliant table rows show a quick "BitLocker +2 more"-style hint under the Compliance pill (full list in a tooltip); the device drawer's existing Compliance & Security card gets a full "Non-Compliant Reasons" chip list, with a fallback message when a non-compliant device genuinely has zero reported reasons (a real, expected outcome when a client's own compliance policy checks nothing specific - not a bug). CSV export gained a `NonComplianceReasons` column.

**A real staleness bug caught before it shipped, not after:** `tenant-store.ts`'s `backfillSnapshot()` picked `devices` by a length comparison (`persisted.length >= mock.length ? persisted : mock`) rather than the "demo tenants always reflect current mock-tenants.ts" rule already used for `users`/`mailboxes`/`signIns` just below it. Adding `nonComplianceReasons` to two existing mock devices didn't change the device *count*, so an already-seeded demo tenant would have silently kept serving devices without the new field forever - the exact class of bug that same file's own comment documents having hit for `signIns` on 2026-09-11 ("found via exactly that... had no visible effect until this was added"). Caught by remembering that precedent while writing this feature, not by rediscovering it live - fixed by switching `devices` to the same `isDemo`-always-mock rule.

**Not live-verified in the browser this pass** - the Claude-in-Chrome extension wasn't connected when this was built; `tsc` is clean, all tests pass (8 new, covering the two mapper functions), and the dev DB has no persisted Contoso Pharmaceuticals snapshot yet (so the staleness fix above hasn't actually been exercised against a real stale row in this environment - only verified correct by direct code inspection against the proven `signIns` precedent). Worth a real click-through (Contoso Pharmaceuticals Ltd demo tenant, devices `CONTRACTOR-DELL-55` and `CP-SEC-019`) the next time the browser tools are available, before treating this as fully done.

Part of [[Clarity365 MOC]]. Devices flagged here are what [[Event Response (Incident Response)]] isolates/scans during an incident. See also [[Defender Configuration & Onboarding]] for the new sibling module (MDE connector settings, the full per-device onboarding report, and Intune/EDR coverage gaps) this same onboarding fetch also feeds.
