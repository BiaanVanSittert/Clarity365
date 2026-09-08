---
tags: [ui]
---

# Overview Dashboard & Fleet Overview Dashboard

Two dashboard components, both lazy-loaded by [[AppShell]]:

## OverviewDashboard
Single-tenant "Top 6 Priority Widgets" home view: Secure Score card, real-time sign-in stream, identity/asset count matrix, license/capability matrix, CA baseline health gauge, high-risk threat indicators. Uses `exchange-mailflow-score` ([[Analysis & Generation]]) and `CA_BASELINE_STANDARDS` ([[Baseline Definitions & Mock Data]]). Renders `StatusPill`, `Skeleton`.

## FleetOverviewDashboard
MSP-wide multi-tenant rollup — the fleet-scale equivalent, reading `FleetPostureSummary`/`FleetTenantPosture` ([[Domain Types]]). Renders `StatusPill`, `Skeleton`; uses `exportToCsv`.

Part of [[Clarity365 MOC]].
