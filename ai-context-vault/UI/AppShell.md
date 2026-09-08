---
tags: [ui, hub]
---

# AppShell

`src/components/layout/AppShell.tsx` :  **the UI's hub node.** Holds `activeView` state and lazy-loads all 24 [[Clarity365 MOC#Modules|modules]] plus both [[Overview Dashboard|dashboards]] via `lazy(() => import(...))`, rendering exactly one at a time based on `activeView`.

Modules never render each other directly :  every navigation is a spoke through AppShell, never module-to-module.

- Wires up: `AddTenantModal`, `DeleteTenantModal`, `SettingsModal`, `PermissionsModal`, `RemediationDrawer`, `SearchDialog`, `GlobalFleetSearchDialog` :  see [[Modals]], [[Common Components]]
- Wraps content in `ErrorBoundary`
- Used by: `Header.tsx` (tenant switcher, global search trigger Ctrl+K) and `Sidebar.tsx` (nav list grouped e.g. "Operations & Governance", "Cost & Optimization"; drives `activeView` changes; shows alert/badge counts)

Part of [[Clarity365 MOC]].
