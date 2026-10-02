---
tags: [ui]
---

# Overview Dashboard & Fleet Overview Dashboard

Two dashboard components, both lazy-loaded by [[AppShell]]:

## OverviewDashboard
Single-tenant "Top 6 Priority Widgets" home view: Secure Score card, real-time sign-in stream, identity/asset count matrix, license/capability matrix, CA baseline health gauge, high-risk threat indicators. Uses `exchange-mailflow-score` ([[Analysis & Generation]]) and `CA_BASELINE_STANDARDS` ([[Baseline Definitions & Mock Data]]). Renders `StatusPill`, `Skeleton`.

## FleetOverviewDashboard
MSP-wide multi-tenant rollup :  the fleet-scale equivalent, reading `FleetPostureSummary`/`FleetTenantPosture` ([[Domain Types]]). Renders `StatusPill`, `Skeleton`; uses `exportToCsv`.

The Posture Matrix table's connection-status column and the Header's per-tenant status badge both now call the shared `getConnectionStatusDisplay()` (`src/lib/utils/tenant-connection-status.ts`) instead of each hand-rolling its own status-to-label ternary - those two independent copies had drifted (one treated any non-healthy/non-degraded status as "Error", the other as "Degraded"), showing conflicting statuses for the same tenant. The table's `statusFilter` state existed but had no UI control wired to it; there's now a Status filter `&lt;select&gt;` next to the Risk/Tier filters.

**Sync all tenants (2026-10-01):** `SyncAllTenantsControl` sits above the fleet table. Start runs a server-side pass (`POST /api/fleet/sync-all`); the control polls the status every 2.5s and shows "Syncing 3 of 10: <tenant>" with the current sync step, a Stop button, and afterwards how many synced, failed (with the reason) or were skipped. It keeps running if the screen is closed, and picks up a pass started by the auto-sync. The fleet table reloads as each tenant finishes. Has a render smoke test. **Reload-loop bug, fixed the same day:** the control asked for a fleet reload on the first status it saw after mounting; the reload showed the skeleton, which unmounted and remounted the control, which asked again, so the fleet view refreshed forever and the button never stayed on screen. Now the first status is only a baseline (`shouldReloadFleet`, with a regression test), and `FleetOverviewDashboard` shows its skeleton only until the first data arrives, so later reloads keep the table on screen.

Part of [[Clarity365 MOC]].
