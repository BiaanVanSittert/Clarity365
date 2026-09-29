---
tags: [module, cost]
---

# Tenant License Optimization

Per-tenant license waste and cost breakdown (the single-tenant lens on the same problem [[Fleet License Optimization]] solves fleet-wide).

- **Component:** `TenantLicenseOptimizationModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Backing call:** `fleet-analyzer.calculateTenantMonthlyWaste`
- **Uses service:** [[Analysis & Generation]] (`fleet-analyzer`)

Six waste categories, not five: `licensed_shared_mailbox`, `inactive_licensed_user` (>90d dormant), `disabled_licensed_user`, `active_licensed_user`, `orphaned_account`, and `unassigned_license_sku` (purchased seats from `TenantLicenseSku[]`/`/subscribedSkus` that nobody's assigned).

**Fixed: every category used to be priced at one flat tenant-tier rate, regardless of which SKU was actually involved.** `unassigned_license_sku` multiplied that flat rate by `sku.availableUnits` - so a $0 self-service SKU with an implausibly large quantity (1,000,000 free `STANDARDWOFFPACK_STUDENT`/`STREAM`/`POWER_BI_STANDARD` seats, 10,000 `FLOW_FREE`, etc. - Microsoft grants these per-org, not per actual purchase) got costed as if it were the tenant's premium paid tier, producing six-and-seven-figure "waste" numbers on real tenants. Fixed by `src/lib/utils/license-sku-costs.ts`'s `getLicenseSkuCostInfo()`: a real per-SKU cost table (`LICENSE_SKU_MONTHLY_COST_USD`, keyed by both Graph's `skuPartNumber` and mock-tenant friendly names - see below), an explicit `FREE_LICENSE_SKUS` set of real, Microsoft-documented $0 SKUs, and a disclosed name-pattern heuristic (`trial`/`viral`/`privpreview`/`exploratory`/`_dev`) for newer/rarer SKUs not worth hand-enumerating - each cost carries a `costBasis` (`confirmed-free` / `known-cost` / `likely-free-by-name` / `unknown-default`) so the UI can show a confirmed "Free" badge differently from a heuristic "Likely Free?" one. An unrecognized SKU defaults to a modest flat rate (`DEFAULT_LICENSE_SKU_COST_USD`, $12), never the tenant's premium tier - the manual per-SKU disable toggle below is the escape hatch for whatever this table still can't know about.

**Manual per-SKU disable toggle**, scoped to this module's own display only (not the shared `calculateTenantMonthlyWaste()` result other consumers read - see [[Analysis & Generation]]): a "Manage Licenses" chip row above the chart, sourced from `src/lib/utils/license-cost-preferences.ts` (localStorage, per-tenant, same convention as `Sidebar.tsx`'s alert-dismissal state). Clicking a chip toggles that SKU out of/into the KPI counts, the `License Utilization by SKU` chart, `monthlyWasteUsd`/`annualWasteUsd`, and the items table all at once - every one of them derives from the same disabled-SKU-filtered `items` array, so there's exactly one filter point, not four separately-maintained ones. The chart itself (`licenseSkuChartData`) is ranked highest-to-lowest by `Total` (enabled units), not left in whatever order Graph/mock data happened to return.

"Last Interactive Sign-In" comes from `resolveUserLastSignIn` in `fleet-analyzer.ts`, which takes the max across three sources: the user's own `lastSignInDateTime` (Graph's `signInActivity.lastSignInDateTime`, fetched live in `graph-client.ts`), the matching `UserMfaProfile.lastSignInDateTime`, and any matching `SignInEvent`. Previously `graph-client.ts` hardcoded `new Date().toISOString()` as the MFA-profile fallback, which made every account (even ones that had never signed in) show "Today" :  fixed by threading the real `signInActivity` value through and falling back to `""`/`undefined` (never signed in) instead of the current timestamp.

Part of [[Clarity365 MOC]]. Depends on [[User & Account Classification]] for the underlying orphan/disabled-seat counts it prices out.
