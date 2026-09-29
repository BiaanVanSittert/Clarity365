---
tags: [optimization, plan, data-protection]
---

# DLP Stage 5: Fleet Rollout (Read-Only Visibility Only)

Plan for the next stage of [[DLP & Sensitivity Labels Plan]]. Status: **planning only, no code written** (drafted 2026-09-22, after the 9-entry catalog and its module shipped - see [[Data Protection (DLP & Sensitivity Labels)]]; revised same day after explicit user direction, see "Hard constraint" below).

## Why this is next
- The recommendation catalog and its module (what the plan originally called Stage 3) are complete: 9 entries, cross-linked, restyled to house convention, verified live.
- Stage 0 (live Purview connectivity) is inconclusive but doesn't block anything built so far - and doesn't block this stage either.
- Stages 1/2 (live sync, posture scoring) remain deferred, and this stage doesn't need them.
- The fleet grew to 9 tenants this session (a new client added), motivating fleet-wide *visibility* into where gaps are.

## Hard constraint (user direction, 2026-09-22): no cross-tenant actions, ever
> "No policy should deploy on multiple tenants at the same time EVER. The ONLY time is when I want to see the general score of all clients/tenants. NEVER to deploy a policy to multiple tenants at the same time."

This is a firm rule for this feature, not a preference to weigh. Consequence: the original draft of this stage (a "per-tenant export, generated for several selected tenants in one action") is **dropped**. Even though generating a document isn't a deployment, it had the shape of one action touching multiple tenants, which is exactly what's ruled out - including in appearance, not just in effect. This stage is now **read-only aggregate visibility, full stop** - no action of any kind originates from the fleet view.

**Context that prompted this:** the user asked what "Fleet Baseline Rollout" was. It's a real, pre-existing feature (`executeBulkCaDeployment()` in `fleet-operations.ts`, used by `FleetBaselineRolloutModule.tsx`) that loops over a selected list of tenant IDs and deploys the same Conditional Access policy to all of them in one action - unrelated to this session's DLP work, but it's what prompted the clarification. **Not touched or changed as part of this plan** - flagged here only as the thing that surfaced the constraint, not something this plan modifies. If the user wants that existing feature revisited against this same principle, that's a separate, explicit ask.

**The DLP catalog itself was already fully compliant with this rule before it was stated** - per the 2026-09-21 deploy-method decision, it has no write path to any tenant at all, single or multiple. This stage's revision is about not even *implying* a multi-tenant action in the UI, not about closing a real gap in what the feature does.

## What this stage now is
A read-only matrix: tenant rows x recommendation columns, showing licence-tier eligibility per tenant per recommendation, so an MSP admin can see at a glance which clients have a gap - nothing more. No button on this view causes anything to happen to any tenant. If the admin wants an actual guidance pack for a specific client, they go to that client's own Data Protection module (already built, already correctly scoped to one tenant) - exactly as it works today. This view adds visibility; it does not add a new action surface.

## Grounding in existing conventions
- Read-only, so it does **not** route through `fleet-operations.ts` at all (that file is specifically for cross-tenant write operations - see [[Fleet Operations]] - and this stage has no write, so it has no business importing it).
- Fleet-scale reads follow the existing convention ([[Fleet Operations]]/[[Data Flow]]: iterate `getAllTenants()`, no separate fleet-level cache).
- Closer in spirit to the read-only side of [[Compliance Matrix (CIS-NIST-Essential 8)]] and the Fleet Posture Matrix's own table than to any of the fleet *deploy* modules (Baseline Rollout, TABL Sync) - deliberately not modeled on those.

## Licence-tier gating: what's available now vs. what's approximate
- Each catalog entry already carries `minimumLicenseTier: "business_premium_e3" | "e5"`.
- Each tenant already carries `Tenant.tier: "M365_E5" | "M365_E3" | "M365_BP" | "M365_F3" | "A5_EDU"` - available today, no live sync required.
- **Caveat, stated plainly rather than glossed over:** `Tenant.tier` is a user-set label, not live-verified entitlement evidence - the exact same distinction [[DLP Stage 1 - Data Model & Licensing]] already draws for `capabilities-mapper.ts`, just without even that live SKU cross-check. `M365_F3` (Frontline) and `A5_EDU` specifically have real-world DLP entitlement nuances not confidently known in this session. The matrix should present tier-gating as a **labeled best-effort estimate**, not a guarantee.
- Deliberately not blocked on Stage 1's live entitlement work - upgradeable later without changing the UI shape, just the data source behind the gating check.

## Proposed shape
- **Placement:** a new top-level sidebar module (e.g. "Fleet Data Protection"), consistent with how the app's other fleet-scale *read* views (Fleet Posture Matrix, Compliance Matrix's fleet mode) already get their own entry. Not a toggle bolted onto the per-tenant module, since this view's whole point is being unambiguously read-only and separate from anything that could ever gain a write action later.
- **Display:** tenant rows x recommendation columns. Each cell: eligible (tier met) / not eligible (tier gap, labeled which tier is required) / not applicable (recommendation's regulation likely doesn't apply - though see the out-of-scope note below). Regulation/data-category filter reused from the existing module to narrow the columns.
- **No action buttons of any kind on this screen.** Clicking a tenant name or cell navigates to that tenant's own Data Protection module (matching `onSelectTenant`, the existing navigation callback already used by other fleet views) - it does not generate or apply anything from the fleet screen itself.
- **Explicitly out of scope for this stage:** letting the admin mark which regulations apply to which specific client is a real, separate feature (a new per-tenant setting), not required for a first version of a read-only matrix. Deferred, not forgotten.

## Sequencing
1. Build the read-only tenant x recommendation matrix, reusing `getAllTenants()` and the existing catalog/filter.
2. Build the tier-gating check as its own small, tested, pure function (e.g. `src/lib/utils/data-protection-tier-gating.ts`) - matching this codebase's established "extract a shared pure function" convention.
3. Wire navigation from a matrix cell/tenant name to that tenant's existing per-tenant Data Protection module - the only "action" this view has, and it's a navigation, not a write.
4. Update the vault and log the `Tenant.tier`-is-a-label-not-evidence caveat in [[Optimization Plan]] alongside the existing mock-versus-live capability bug class it's a variant of.

## What stays true from earlier stages
- Still zero live writes, zero live Purview reads.
- Still no dependency on Stage 0/1/2.
- The catalog content itself (portal steps, PowerShell templates, caveats) is unchanged and stays exactly where it already lives, one tenant at a time.

## Shipped (2026-09-22)
`FleetDataProtectionModule.tsx` is live - sidebar entry "Data Protection Visibility" under Operations & Governance (Fleet Command view), next to Compliance Matrix. `src/lib/utils/data-protection-tier-gating.ts` (tested, `getTierEligibility()`) is the pure function behind the matrix cells. Verified live: all 9 tenants x 9 recommendations render correctly (A5_EDU and E5 tenants show eligible on the E5-only `ip-contracts-source-code` column, every other tier shows the "needs E5" warning as expected), and clicking a tenant name navigates straight to that tenant's own single-tenant Data Protection module - the only interaction this screen has, and it's a navigation, not an action. No export, no multi-tenant button, no write path - matches the hard constraint above exactly. `tsc` clean; test suite 47 files / 564 tests (three new for the gating function).

Part of [[DLP & Sensitivity Labels Plan]] and [[Clarity365 MOC]].
