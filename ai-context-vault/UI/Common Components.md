---
tags: [ui]
---

# Common Components

The shared "table/panel kit" under `src/components/common/` that nearly every module composes from — this is why the whole app looks and behaves consistently despite 24 independently-built modules.

- **Modal.tsx** — base modal shell; used by 8 of 11 [[Modals]] + several modules
- **Drawer.tsx** — base slide-out drawer shell; used by [[Event Response (Incident Response)]], [[Groups & Distribution Management]], [[Intune Endpoint Security]], [[Sign-In Logs & CA Diagnostics]], and `RemediationDrawer`
- **StatusPill.tsx** — colored status badge; used by 14+ modules, both dashboards, SettingsModal, RemediationDrawer, PermissionsModal — the single most-reused component in the codebase
- **EmptyStateRow.tsx** — "no data" table filler; used across 9 modules
- **Pagination.tsx** — table pager; used by [[Audit Log Viewer]], [[Event Response (Incident Response)]], [[Sign-In Logs & CA Diagnostics]]
- **SkeletonLoader.tsx** (`Skeleton`/`SkeletonLoader`) — loading skeleton; both dashboards, [[Fleet License Optimization]], [[AppShell]]
- **LocalOnlyNotice.tsx** — "this data is local-only, not yet pushed to M365" banner; [[Groups & Distribution Management]], [[Defender for Office 365 & TABL]], [[SharePoint & Storage Policies]]
- **ErrorBoundary.tsx** — top-level React error boundary wrapping module content in [[AppShell]]
- **GlobalFleetSearchDialog.tsx** — Ctrl+K cross-tenant search overlay, triggered from Header, rendered in AppShell
- **SearchDialog.tsx** — simpler/single-tenant search variant, rendered in AppShell alongside the above
- **table-dense (globals.css)** — the shared high-density table grid styling used across 20+ modules. Supports row hover outlines (`outline: 1px solid #94a3b8` light / `#475569` dark with `outline-offset: -1px`), alert outlines for critical (`#ef4444`) and warning (`#f59e0b`) rows, and strictly preserves custom background highlights (`bg-red`, `bg-amber`) on hover across both light and dark modes instead of overwriting cell backgrounds.

Part of [[Clarity365 MOC]].
