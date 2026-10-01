---
tags: [module, conditional-access]
---

# Sign-In Logs & CA Diagnostics

Real-time sign-in log streamer with CA rule-chain inspector, error-code translation, timeframe presets/custom date range, and a KQL generator.

- **Component:** `SignInLogsModule.tsx`
- **Reads:** `TenantSecuritySnapshot.signIns` (prop-driven)
- **Key types:** `SignInEvent`, `TimeRangePreset`, `CustomDateRange` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Drawer`, `Modal`, `Pagination`
- **Data origin:** [[Core Graph Layer]] (`graph-client.fetchLiveTenantSnapshot`) pulls sign-ins live with failure reasons and report-only evaluation

Also fixed: the sidebar's badge for this module (`riskySignInsCount` in `Sidebar.tsx`, and this module's own "Mark All Reviewed" button) used to be a plain sticky dismiss flag stored per-tenant in `localStorage` (`clarity365_alerts_cleared_<tenantId>`) - once cleared it stayed hidden forever, even as new risky/CA-blocked/failed sign-ins kept happening, since nothing ever compared against new data. Sign-in logs are an event stream, not a point-in-time state like the other 11 sidebar badges, so that model was wrong for it specifically. Replaced with a "reviewed through &lt;timestamp&gt;" watermark (`src/lib/utils/sign-in-review-watermark.ts`, shared by `Sidebar.tsx` and `SignInLogsModule.tsx` so the two can't drift apart the way earlier fixes this session found duplicated logic doing): clearing records the latest flagged sign-in's timestamp, and the badge only counts events created after it - so it clears now and comes back on its own for genuinely new activity, without needing a manual "restore." This badge is also now exempt from the sidebar's blanket "Clear Badges" mute-everything toggle (which the other 11 badges still use), since muting a live event stream indefinitely was never the right fit either.

## Country breakdown, flags, and "outside home country" filter

- **Format convention:** `SignInEvent.location.country` is always an ISO 3166-1 alpha-2 code (e.g. `"US"`), uppercase - verified against Microsoft's own `signInLocation` resource reference ("the country code info (two letter code)"). Mock data used to store full names instead (`"United States"`) until normalized to match - see [[Domain Types]] and [[Optimization Plan]] item 7's "two representations of one fact" pattern.
- **Utility:** `src/lib/utils/sign-in-country.ts` (has a test) - `getCountryDisplayName()` wraps the built-in `Intl.DisplayNames` (no new dependency) to resolve a code to a friendly name; `summarizeSignInsByCountry()` groups events by code with a dedicated `"unknown"` bucket for anything missing/malformed; `detectMostCommonCountry()` picks the Home Country auto-detect default.
- **Flags:** the `flag-icons` npm package (real local SVG assets, no emoji, no external network calls), imported once globally in `src/app/layout.tsx`. Rendered through the one shared `CountryFlag` component (`src/components/common/CountryFlag.tsx`) everywhere a flag appears (this module's chip bar/table/drawer, and `OverviewDashboard.tsx`'s recent-activity widget) so the "unknown -> globe icon" fallback can't drift between call sites.
- **UI:** a "Sign-ins by Country" chip bar (same click-to-filter convention as the Frequent Error Codes bar) plus a Home Country `<select>` (defaults to the auto-detected most common country, always overridable) and an "Outside Home Country" toggle - the literal ask behind this feature, for spotting an unusual-origin sign-in at a glance. All backed by one `countryFilter` state slotted into the existing filter pipeline exactly like `statusFilter`/`serviceFilter`/`errorCodeFilter` already were.
- **Related fix:** `fleet-analyzer.ts`'s Universal Search now also matches a sign-in's resolved country *name*, not just the raw stored code - previously a live tenant's "US"-coded events were never found by typing "united states".
- **A second, deeper bug this surfaced:** `tenant-store.ts`'s `backfillSnapshot()` already had a "demo tenants always reflect the current `mock-tenants.ts`, never the value frozen in the database at first seed" rule for `users`/`mailboxes`/`devices`/`incidents` - but `signIns` was missing from that list. A demo tenant seeded before any mock-data edit kept serving its stale, already-persisted `signIns` forever (mock tenants never re-sync - `fetchLiveTenantSnapshot` short-circuits unchanged for `authMode === "mock"`), which is exactly how the country-code normalization above initially appeared to have no effect at all. Fixed by adding `signIns` to that same backfill rule.

## Coverage line and Sign-in report (2026-10-01)
- A line under the sync-error banner states which period the list really covers (`getSignInCoverage` + `describeSignInCoverage`); orange when only the newest sign-ins were loaded or loading stopped early.
- **Sign-in report** button opens `SignInReportModal`: summary by country, IP address, user, MFA method, app, client and device, "worth a look" findings, a printable report and CSV downloads. It uses the module's home country. See [[Sign-in Report]].

Part of [[Clarity365 MOC]]. Tightly coupled to [[Conditional Access Policy Scanner]] :  this is where a CA policy's report-only failures actually surface per-user.
