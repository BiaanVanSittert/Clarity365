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

Part of [[Clarity365 MOC]].
