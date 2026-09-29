---
tags: [module, compliance, data-protection, fleet]
---

# Fleet Data Protection Visibility

Read-only cross-tenant matrix for [[Data Protection (DLP & Sensitivity Labels)]]'s catalog. See [[DLP Stage 5 - Fleet Rollout]] for the full plan and the hard constraint this module exists to satisfy.

- **Component:** `FleetDataProtectionModule.tsx`
- **Sidebar:** Operations & Governance (Fleet Command view), next to Compliance Matrix
- **Props:** `tenants: Tenant[]`, `onSelectTenant` - no `snapshots` dependency, unlike most fleet views, since it only needs each tenant's `tier` label and the static catalog
- **Uses:** `src/lib/utils/data-protection-tier-gating.ts` (`getTierEligibility()`, tested) - maps a tenant's `Tenant.tier` label against a recommendation's `minimumLicenseTier`

## Hard rule this module exists to satisfy
Per explicit user direction (2026-09-22, recorded in [[DLP & Sensitivity Labels Plan]]'s cross-cutting rules and in memory as `no-cross-tenant-actions`): no action of any kind may ever touch more than one tenant at once in this feature. This module is **read-only aggregate visibility only** - the one exception that rule explicitly allows ("the general score of all clients/tenants"). There is no button, export, or generated document on this screen. Clicking a tenant name is a **navigation** (to that tenant's own already-single-tenant Data Protection module), not an action.

## What it shows
Tenant rows x recommendation columns. Each cell: a green check (tier eligible), an amber warning (needs E5), or a gray question mark (tier entitlement not confirmed - currently only `M365_F3`, since its real DLP entitlement wasn't confidently known when the gating function was written). Reuses the existing regulation/data-category filter from `DataProtectionModule.tsx`.

## Known caveat, surfaced in the UI itself
`Tenant.tier` is a user-set label, not live-verified entitlement evidence - the same distinction [[DLP Stage 1 - Data Model & Licensing]] draws for `capabilities-mapper.ts`'s live checks, just without even that live SKU cross-check. The module's own footer states this plainly rather than letting the matrix imply more certainty than it has.

Part of [[Clarity365 MOC]].
