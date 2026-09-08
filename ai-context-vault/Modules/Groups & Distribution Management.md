---
tags: [module]
---

# Groups & Distribution Management

Security/M365-Unified/DL group management with an interactive group creator; flags role-assignable groups (`isAssignableToRole`) as admin-grant risk.

- **Component:** `GroupsManagementModule.tsx`
- **API routes:** `POST /api/tenants/{id}/groups`
- **Key types:** `TenantGroup` — see [[Domain Types]]
- **Renders:** `StatusPill`, `Modal`, `Drawer`, `LocalOnlyNotice`, `EmptyStateRow`
- **Uses service:** [[Baseline Matchers]] (`groups-baseline-matcher`)
- **Baseline source:** [[Baseline Definitions & Mock Data]] — `GROUPS_BASELINE_STANDARDS` (7 rules, none auto-fixed yet)

Part of [[Clarity365 MOC]].
