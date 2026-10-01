---
tags: [ui, hub]
---

# AppShell

`src/components/layout/AppShell.tsx` :  **the UI's hub node.** Holds `activeView` state and lazy-loads all 24 [[Clarity365 MOC#Modules|modules]] plus both [[Overview Dashboard|dashboards]] via `lazy(() => import(...))`, rendering exactly one at a time based on `activeView`.

Modules never render each other directly :  every navigation is a spoke through AppShell, never module-to-module.

- Wires up: `AddTenantModal`, `DeleteTenantModal`, `SettingsModal`, `PermissionsModal`, `RemediationDrawer`, `SearchDialog`, `GlobalFleetSearchDialog` :  see [[Modals]], [[Common Components]]
- Wraps content in `ErrorBoundary`
- Sidebar group **Security Simulations** (after Identity & Access): `sim_scenarios` → [[Security Scenarios]] (badge: red scenarios), `sim_signin` → [[Sign-in Situations]], `sim_ca_gaps` → [[CA Gap Analysis]] (badge: critical + high findings). AppShell holds `simPersona` so a scenario check or a gap can open Sign-in Situations on the right persona
- Used by: `Header.tsx` (tenant switcher, global search trigger Ctrl+K) and `Sidebar.tsx` (nav list grouped e.g. "Operations & Governance", "Cost & Optimization"; drives `activeView` changes; shows alert/badge counts)

**Header additions (2026-10-01):** next to the sync status, "N permissions missing" (from `syncHealth.missingPermissions`, opens the Permissions check) and a "Secret expires in N days" / "Secret expired" badge (from `getSecretExpiryStatus`). The fleet table shows the same expiry warning under each tenant's sync status, read-only.

Part of [[Clarity365 MOC]].
