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

Part of [[Clarity365 MOC]]. Tightly coupled to [[Conditional Access Policy Scanner]] :  this is where a CA policy's report-only failures actually surface per-user.
