---
tags: [service, simulation, ca]
---

# CA Simulation Engine

The Conditional Access "What If" engine behind every Security Simulations view (see [[Security Simulations Plan]], Stage 2). Three pure files in `src/lib/services/`, each with a test. **Nothing else should re-derive "does this CA policy apply to this sign-in" inline**: that is the duplicated-logic bug class in [[Optimization Plan]] item 7.

## ca-policy-evaluator.ts : the engine
`evaluateSignIn(ctx, env)` takes one `SignInContext` (user, target resource or user action, client app type, platform, device state, optional device-code / authentication-transfer flow, country + IP named locations, sign-in / user / insider risk) and a `CaEnvironment` (policies, named locations, groups, P2 licensing, security defaults), and returns:
- `enforced`: what actually happens, from enabled policies only: `blocked` / `challenged` / `allowed` / `indeterminate`, plus which policies block, what each requires (MFA, phishing-resistant MFA, app protection, password change...) and session controls.
- `withReportOnly`: what would happen if every report-only policy were switched on.
- `reportOnlyHits`: report-only policies that would block or challenge.
- `trace`: one row per policy with **why** it did or didn't apply (disabled, excluded via X, app not in scope, location excluded, needs P2, synced before simulation support...).

Rules worth knowing:
- Exclusions beat inclusions. Unconfigured conditions match everything.
- Grant: `block` wins; `compliantDevice` / `domainJoinedDevice` / app protection that the context can't satisfy count as blocked; `mfa` and authentication strengths are "challenged". OR/AND comes from `grantOperator`; when unsynced it's assumed AND with password change, OR otherwise (with a note).
- Risk conditions need Entra ID P2 (`hasEntraP2Capability()`); without it the policy "never evaluates".
- **Three-valued**: anything the engine can't determine (device filters, a group missing from the capped groups list, unresolvable role names, unsynced named locations) is `unknown` → `indeterminate`, never guessed.
- **Live policies synced before Stage 1 are `unknown`** (`env.incompletePolicyIds`). Found live on 2026-09-29: Zubat Nine's "Microsoft-managed: Block device code flow", stored by the old mapper without its `authenticationFlows` condition, read as "block everything". A groups-only policy would read as "targets nobody". The engine refuses to guess in either direction.
- Handles both CA identifier dialects: Graph ids and the demo/local-write markers (`DirectoryRole:*`, `AllAdmins`, `upn:`, `group:`, `loc:`). Role references go through `directory-role-templates.ts`.
- Security defaults on and no enabled CA policy → evaluated as three synthetic policies (legacy block, admin MFA, user MFA).
- User actions (`registersecurityinfo`, `registerdevice`) are only covered by policies that name them.

## ca-sim-context.ts : inputs from a snapshot
`buildCaEnvironment(snapshot)`, `buildSimUser(snapshot, userId)` (roles from `UserMfaProfile.adminRoleTemplateIds`, falling back to role names; groups by direct UPN membership), `buildSyntheticSimUser(kind)`, `listSimAccounts(snapshot)` (the "Sign in as" lists: Global Admins, other admins, standard users, guests; each flagged `roleSource` directoryRoles/inferred and `breakGlassReasons`), and `detectLikelyBreakGlassAccounts(snapshot)` (named like one, or excluded from at least 60% of active policies). Break-glass accounts are **warned about, never silently treated as intended** (user decision, see the plan).

## ca-fix-recommender.ts : proven fixes
`recommendFixes(ctx, env, desired, options)` re-runs the evaluator on modified copies of the tenant, so every suggestion is proven by the engine itself. The order of what it tries:
1. Enable a report-only policy (alone, or together if none suffices alone).
2. Review an exclusion that stops an otherwise-effective policy, with a break-glass warning when the excluded account looks like one.
3. Check policies whose applicability is uncertain.
4. Deploy the matching CA01-CA10 baseline if it isn't enabled.
5. Create a new policy (described by the caller).
Desired outcomes: `block`, `strongAuth`, `phishingResistant`, `passwordChange`, `appProtection`.

## Live validation (2026-09-29)
Run read-only against all nine synced tenants. Findings that shaped the code: a real CA08 targets app `"None"` (never applies), break-glass exclusions are by user GUID, the first Global Admin in two tenants is the break-glass account (hence `breakGlassReasons` in the picker), and the stale-scheduler problem below.

**Dev-server caveat:** the background auto-sync scheduler runs whatever code existed when the server started (see [[Tenant Store]]). A server started before Stage 1 **overwrote** freshly-synced Stage 1 data with old-shape snapshots every 30 minutes. Restart the dev server (`npm run restart`) after any change to the sync code, then re-sync. From schema version 2 onward a stale build refuses to overwrite newer snapshots (see [[Tenant Store]]).

## Stage 3 additions
- Guests: risk-based policies never apply to a guest with risk (Microsoft evaluates guest risk in the home tenant).
- `recommendFixes` options take a `normalContext`; a fix that would also block it gets `sideEffect` and is ranked after targeted fixes. A `licence` fix leads risk situations when P2 is missing.
- `listSimAccounts` marks `excludedFrom` (policies that exclude the account by id or UPN); `pickTypicalAccount` prefers accounts with neither exclusions nor break-glass signs.

## Stage 4 additions
- `riskRemediation` grant control → a remediation requirement (same kind as password change).
- `securityDefaultsPolicies()` exported so [[CA Gap Analysis]] can read the synthetic policies' controls.
- Break-glass detection also flags accounts excluded from at least 60% of **enforced** policies (Microsoft: report-only policies don't need the exclusion).

Consumers: [[Sign-in Situations]], [[CA Gap Analysis]] (built); Scenarios (planned). Part of [[Clarity365 MOC]].
