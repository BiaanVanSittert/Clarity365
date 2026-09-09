---
tags: [module, cost]
---

# Tenant License Optimization

Per-tenant license waste and cost breakdown (the single-tenant lens on the same problem [[Fleet License Optimization]] solves fleet-wide).

- **Component:** `TenantLicenseOptimizationModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Backing call:** `fleet-analyzer.calculateTenantMonthlyWaste`
- **Uses service:** [[Analysis & Generation]] (`fleet-analyzer`)

Six waste categories, not five: `licensed_shared_mailbox`, `inactive_licensed_user` (>90d dormant), `disabled_licensed_user`, `active_licensed_user`, `orphaned_account`, and `unassigned_license_sku` (purchased seats from `TenantLicenseSku[]`/`/subscribedSkus` that nobody's assigned :  priced at the tenant's per-seat tier cost same as every other category, and counted into `monthlyWasteUsd`).

"Last Interactive Sign-In" comes from `resolveUserLastSignIn` in `fleet-analyzer.ts`, which takes the max across three sources: the user's own `lastSignInDateTime` (Graph's `signInActivity.lastSignInDateTime`, fetched live in `graph-client.ts`), the matching `UserMfaProfile.lastSignInDateTime`, and any matching `SignInEvent`. Previously `graph-client.ts` hardcoded `new Date().toISOString()` as the MFA-profile fallback, which made every account (even ones that had never signed in) show "Today" :  fixed by threading the real `signInActivity` value through and falling back to `""`/`undefined` (never signed in) instead of the current timestamp.

Part of [[Clarity365 MOC]]. Depends on [[User & Account Classification]] for the underlying orphan/disabled-seat counts it prices out.
