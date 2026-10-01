---
tags: [module, simulation, ca]
---

# Sign-in Situations

`src/components/modules/SignInSituationsModule.tsx`, view id `sim_signin`, sidebar group **Security Simulations** (after Identity & Access). Stage 3 of the [[Security Simulations Plan]]. Read-only and tenant-scoped; nothing is sent to Microsoft.

## What it does
"Sign in as" a real account (Global Admins plus an "other admin roles" group, standard users, or guests; or a hypothetical account when a persona has none), pick a home and a foreign country, and see each of the 26 situations evaluated against the tenant's synced Conditional Access policies by the [[CA Simulation Engine]].

Per situation: a verdict, one outcome line naming the blocking or challenging policy, "why it isn't blocked" (exclusions, report-only policies, licence or guest-risk limits), ranked fixes, matching events from the account's own synced sign-in log, notes and caveats, and a per-policy trace table.

## Colour rules (user decisions, see the plan)
- **Green, Prevented**: blocked.
- **Orange, Allowed after MFA / checks**: allowed only after MFA, phishing-resistant MFA, app protection or a password change. Any MFA outcome is orange, by decision.
- **Red, Not prevented**: allowed with nothing stopping it.
- **Orange (dashed), Can't confirm**: the engine couldn't determine the result (policies synced before simulation support, device filters, no trusted locations defined...).
- Good-path case (`guest-browser-known`): allowed after MFA is green ("Working as intended"), a block is orange.

## Files
- `src/lib/data/signin-situation-definitions.ts`: the 26 situations as data (8 Global Admin, 11 standard user, 7 guest). **Each changes one risky attribute from `PERSONA_NORMAL`**, and `normal` is its benign twin, used to rank fixes. Location kinds: `home`, `foreign`, `trusted` (inside trusted IP named locations), `untrustedIp`.
- `src/lib/services/signin-situation-runner.ts`: builds contexts, applies the colour rules (`classifySituation`), explains why a sign-in isn't blocked, gathers fixes and log evidence; `detectHomeCountry` (most common sign-in country, else the first country named location).
- `src/lib/utils/iso-country-codes.ts`: ISO 3166-1 codes for the country pickers (names via `sign-in-country.ts`).
- Tests: `signin-situation-runner.test.ts` (demo tenants), `SignInSituationsModule.test.ts` (server-render smoke test, the repo's first component test; see [[Testing]]).

Accepts an optional `initialPersona` prop so [[CA Gap Analysis]] can open it on the persona behind a gap.

## Picker defaults
The account picker starts on a **typical** account (`pickTypicalAccount`): not a likely break-glass account and not individually excluded from any policy. Found live: Zubat Nine's first standard user is individually excluded from both the MFA and legacy-auth policies, so defaulting to it made a well-protected tenant look open (10 of 11 red, versus 0 for every other user). Excluded and break-glass accounts are marked in the list with a warning when selected.

## Live validation (2026-09-29, read-only, seven re-synced tenants)
Results matched each tenant's policies. Real gaps it surfaced: guests at Axiomatic and Wauko have no enforced policy (CA02 excludes guests, CA04 is report-only); Gustav Barkhuysen has every policy in report-only; no live tenant defines trusted IP locations except Wauko, so "known location" situations elsewhere read "No trusted locations".

**2026-10-01:** the evidence line ("N synced sign-ins by this account look like this situation") now also states the period the sign-in log covers, so "none found" isn't read as "never happened". Admins whose roles couldn't be read show "Administrator (role not confirmed)" instead of a made-up Global Administrator.

Part of [[Clarity365 MOC]].
