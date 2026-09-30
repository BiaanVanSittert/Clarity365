---
tags: [module, simulation]
---

# Security Scenarios

`src/components/modules/SecurityScenariosModule.tsx`, view id `sim_scenarios`, first entry of the sidebar's **Security Simulations** group, with a badge counting red scenarios. Stage 6 of the [[Security Simulations Plan]]. Read-only and tenant-scoped.

## What it does
17 attack scenarios in four sections (Identity & Conditional Access 9, Audit & Detection 3, Exchange & Email 2, SharePoint & Data 3). Each is a list of **checks**, the defensive layers that would stop it, and each check returns prevented / partial / not prevented / not assessed with a detail, the offending items (capped at 12), a fix, a verified Microsoft Learn link, and optionally "Simulate sign-ins" for the persona involved. Each scenario card shows "N checks: X prevented · Y partial · Z not prevented · W not assessed" and its gap count (partial + not prevented).

**Verdict roll-up** (`rollUpVerdict`): red if **any** check is not prevented (a single open path lets the attack through), green only when every check is prevented, orange otherwise (partial or not-assessed checks). Chosen to match the user's "green and red mainly" decision. On live tenants this makes most scenarios red, because checks like token protection and a device-registration policy are rarely in place.

## Logic: `src/lib/services/security-scenarios.ts`
`evaluateScenarios(snapshot)` builds one context: the CA environment, the [[CA Gap Analysis]] result, the account lists, break-glass candidates, and a cached [[Sign-in Situations]] runner. **Checks that are really sign-in questions reuse those** (`fromSituation`, `fromCell`, plus direct engine probes for device registration, security-info registration, unknown countries and authentication transfer), so the three views can't disagree. Non-CA checks read Stage 5 data: Exchange audit and protocol settings, SharePoint security settings, PIM role assignments, OAuth consent grants, identity settings, mail forwarding, transport rules, MDO outbound policies, app registrations.

Not-assessed is used, never green, when: Exchange isn't connected, data wasn't synced, the OAuth permission is missing (names DelegatedPermissionGrant.Read.All), PIM data is unavailable, Graph doesn't report a SharePoint link default, or a check is manual (alert policies for audit changes and mass deletion; Clarity365 can't read alert policies).

The **Anyone link** scenario always shows the user-decided warning that sensitivity labels aren't synced, so every site is checked. It deliberately does **not** use `SharePointSiteItem.isSensitiveDataPresent`, which is a site-name keyword heuristic.

New helper: `src/lib/utils/intune-capability.ts` (`hasIntuneCapability`), recognising both the live `cap-intune` and demo `cap-intune-*` ids.

## Engine changes made in Stage 6 (see [[CA Simulation Engine]])
- **Partial resource coverage.** A policy covering only part of Office 365 (for example SharePoint only) no longer counts as blocking or challenging the whole sign-in; it's reported as `partialCoverage`. Found in Stage 6 testing: Northwind's SharePoint-only compliant-device policy read as "guests from abroad are blocked" while Exchange and Teams stayed open. Sign-in Situations shows these as orange "Partly blocked"; the gap grid doesn't count them as covering a persona.
- **Synthetic users' group membership is complete.** For the hypothetical persona users (scenarios, gap grid), a group missing from the capped synced group list is a definite "no", not "unknown". Found live: a tenant with more groups than the sync fetches read "can't confirm" on almost every tenant-wide question.

Tests: `security-scenarios.test.ts` (catalog, roll-up, demo tenants), `SecurityScenariosModule.test.ts` (render smoke test), `intune-capability.test.ts`.

Part of [[Clarity365 MOC]].
