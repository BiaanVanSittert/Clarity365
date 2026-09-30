---
tags: [optimization, plan, ca, simulation]
---

# Security Simulations - Plan

Status: **reviewed 2026-09-29. Stages 1-6 built 2026-09-29/30; the booked lint cleanup done 2026-09-30. Remaining: Stage 7 (optional polish, pick and choose).**

## Decisions (user review, 2026-09-29)
1. **Colours**: green (prevented) and red (not prevented) are the main states. **Orange** is used only where needed: partial coverage, report-only, and "not assessed" states.
2. **Allowed after MFA = orange**, for every situation. It is neither a clean block (green) nor unprotected (red). This replaces the per-situation "Challenged counts as prevented" idea in Stage 3: a challenged outcome always renders orange.
3. **Build order as recommended**: engine, then Sign-in Situations, then CA Gap Analysis, then Scenarios.
4. **Break-glass accounts**: no operator setting. The analysis detects likely emergency-access accounts (for example accounts excluded from every policy, or named like "breakglass"/"emergency") and shows a **warning** so the operator can confirm, rather than silently treating the exclusion as intended or as a gap.
5. **Sensitive sites**: no heuristic or list. The "Anyone link on a sensitive site" scenario shows a warning that sensitivity labels are not yet synced (see [[Sensitivity Labels Catalog Plan]]), so sensitivity can't be determined, and evaluates Anyone-link exposure across all sites.

User request: a new sidebar category, **Security Simulations**, with three views:
1. **Scenarios** : attack scenarios grouped by area (Identity & Conditional Access, Audit & Detection, Exchange & Email, SharePoint & Data), each showing a green/red prevented/not prevented verdict and a count of gaps.
2. **Sign-in Situations** : "sign in as" a real Global Admin, a standard user, a guest, or from a foreign country, and see which Conditional Access policy blocks each situation, or why it is allowed and what would fix it.
3. **CA Gap Analysis** : a Conditional Access score out of 10, a persona x control coverage heatmap, and a severity-ranked findings list (reference screenshot: score card, "Coverage by persona" grid with Enforced / Report-only / No policy / Unlicensed / Not applicable, then "Policy findings" with severity, source, affected policies, fix and a Microsoft Documentation link).

Scope rule (see memory "no cross-tenant actions"): all three views are **per tenant and read-only**. Fix suggestions deep-link into existing single-tenant flows (for example the CA module's deploy path); this plan adds no new write path and no fleet-wide action.

## Guiding decisions

1. **One evaluation engine, three views.** The biggest risk here is the recurring bug class in [[Optimization Plan]] item 7: the same "does this policy apply / what does it mean" logic written again in each view and then drifting apart. So the core is one pure, tested module, `ca-policy-evaluator.ts`, which answers *"for this user, in this sign-in context, which policies apply and what is the outcome?"* Sign-in Situations calls it directly. CA Gap Analysis calls it per persona. Identity scenarios call it with preset contexts. Nothing re-derives policy applicability inline.
2. **Build order differs from the listed order: engine, then Sign-in Situations, then CA Gap Analysis, then Scenarios.** Sign-in Situations is the most direct test of the engine, the Gap Analysis is a summary over it, and the Scenarios reuse both plus extra non-CA data. Building Scenarios first would mean writing their CA checks twice.
3. **Computed client-side from the snapshot**, like every other module's read path ([[Data Flow]]). No new API routes are needed for the core feature. Results are only as fresh as the last sync, so every view shows "Evaluated against policies synced at <time>".
4. **Never show green for missing data.** Besides green (prevented) and red (not prevented), use **amber = partially prevented** and **grey = not assessed** (data not synced, permission missing, licence absent, or a condition the engine cannot evaluate). A green tick produced by an empty array is exactly the "mock data makes it look finished" variant in [[Optimization Plan]]. *(Open question 1.)*
5. **Each situation and scenario states its own desired outcome.** "Allowed after MFA" is enough for "Standard user, high sign-in risk" but not for "stolen session token replay" (MFA was already satisfied inside the stolen token). The verdict compares the engine's outcome with that desired outcome; it is not a simple "was it blocked".

## Stage 1 : Data foundation (sync completeness)

Nothing in the later stages can be correct until the snapshot keeps the CA fields they depend on. `mapConditionalAccessPolicy()` in [[Core Graph Layer]] currently keeps users (include/exclude/excludeGroups/includeRoles, guests as a marker), applications, clientAppTypes, platforms, locations (raw GUIDs), and user/sign-in risk levels. It **drops** the fields below. All new fields are optional, per the tenth bug-class variant (no snapshot migration system).

| New `CAPolicyRule` field | Graph source | Needed for |
|---|---|---|
| `conditions.users.includeGroupIds` | `includeGroups` (currently dropped; only `excludeGroups` is kept) | Any policy scoped to a group. Without it such policies look "All users" or "nobody" |
| `conditions.users.excludeRoles` | `excludeRoles` | Admin exclusions |
| `conditions.users.guestTypes` | `include/excludeGuestsOrExternalUsers.guestOrExternalUserTypes` | Guests: which guest types a policy covers |
| `conditions.applications.userActions` | `includeUserActions` (`urn:user:registersecurityinfo`, `urn:user:registerdevice`) | MFA tampering scenario, device registration finding |
| `conditions.applications.authenticationContexts` | `includeAuthenticationContextClassReferences` | Protected actions (mass deletion scenario) |
| `conditions.authenticationFlows` | `authenticationFlows.transferMethods` (`deviceCodeFlow`, `authenticationTransfer`) | Device-code and authentication-transfer situations |
| `conditions.insiderRiskLevels` | `insiderRiskLevels` | "Elevated insider risk" situation |
| `conditions.devices` | `devices.deviceFilter` (mode + rule) | Stored as-is; evaluated as **grey / indeterminate**, not parsed (rule syntax is a mini-language) |
| `conditions.clientApplications` / `servicePrincipalRiskLevels` | workload identity targeting | Workload identities row |
| `grantOperator` | `grantControls.operator` (`AND`/`OR`) | Currently lost; "MFA **or** compliant device" and "MFA **and** compliant device" mean very different things |
| `sessionControls` | `signInFrequency`, `persistentBrowser`, `applicationEnforcedRestrictions`, `cloudAppSecurity`, `secureSignInSession` (token protection), `continuousAccessEvaluation` | Token replay, session limits column, bulk-sync scenario |

New tenant-level data (one sync step each, same try/catch and `syncErrors` resilience as every other step; `TOTAL_SYNC_STEPS` goes from 20 to roughly 23):

| Data | Endpoint | Permission | Notes |
|---|---|---|---|
| Named locations | `GET /identity/conditionalAccess/namedLocations` | `Policy.Read.All` (already held) | Resolves location GUIDs to country lists (`countriesAndRegions`, `includeUnknownCountriesAndRegions`, `countryLookupMethod`) or IP ranges plus `isTrusted`. Without this, "foreign country" cannot be evaluated |
| Security defaults | `GET /policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | If on, CA cannot be used at all; the engine models the defaults' own behaviour instead and the views show a banner |
| Authorization policy | `GET /policies/authorizationPolicy` | `Policy.Read.All` | User consent setting (`permissionGrantPoliciesAssigned`), guest role (`guestUserRoleId`), guest invite setting. Needed for the OAuth consent and guest scenarios |
| Admin consent workflow | `GET /policies/adminConsentRequestPolicy` | `Policy.Read.All` | OAuth consent scenario |

A pure helper, `directory-role-templates.ts`, holds **one** constant map of well-known role template GUIDs to names. CA stores `includeRoles` as template GUIDs but `UserMfaProfile.adminRoles` holds display names, and this map is the only safe bridge between them. Single source, per the third bug-class variant (copied literals).

Mock data: extend all four demo tenants in `mock-tenants.ts` so the three views have something meaningful to show: Woodgrove Zero-Trust mostly green, Contoso E5 mixed with report-only policies, Fabrikam E3 with unlicensed risk cells (no P2), Northwind Business Premium with typical small-business gaps. Check `backfillSnapshot()`'s demo-field refresh list in [[Tenant Store]] if any new field needs to follow mock edits.

**Done when:** new mapper fields are covered in `graph-client.test.ts` (using real Graph response shapes, including the structured guest field that already bit CA04), the new sync steps degrade gracefully, and a live sync against one real tenant populates them. This is the only stage that touches hub files (`types/index.ts`, `graph-client.ts`); read their vault notes first.

### Stage 1 build record (2026-09-29)
Built: `ca-environment-mapper.ts` (+ test), `directory-role-templates.ts` (+ test), `demo-ca-policy-merge.ts` (+ test), `mock-tenants.test.ts`, new types, sync steps 21-22 (`TOTAL_SYNC_STEPS` 20 to 22), demo data for all four tenants, and the demo refresh in `backfillSnapshot()`. Type-check, lint and 605 tests pass. **Still open: one live sync against a real tenant** to confirm the new fields and the beta session read populate as expected.

Findings made while building, which change later stages:
- **Token protection and CAE are beta-only** (confirmed on Microsoft Learn). They're filled from a separate best-effort beta read, so the engine must treat undefined as "not assessed" (orange), not "off".
- **Two CA identifier dialects coexist.** Live policies use Graph ids (role template GUIDs in `includeRoles`, group GUIDs, named-location GUIDs, `"All"`, `"GuestsOrExternalUsers"`). Demo data *and* the local post-deploy writes in `tenant-store.ts`, `drift-analyzer.ts` and `fleet-operations.ts` use markers (`"DirectoryRole:GlobalAdmin"`, `"AllAdmins"`, `"upn:..."`, `"group:..."`, `"loc:..."`). Stage 2 must resolve both in one place: `directory-role-templates.ts`'s `resolveCaRoleReference()` already covers roles; users, groups and locations need the same treatment. Demo named-location ids were chosen to equal the `"loc:"` markers so location lookups work unchanged.
- **The local post-deploy policy payload is duplicated three times** (`tenant-store.ts` `deployBaselinePolicy`, `drift-analyzer.ts`, `fleet-operations.ts`). Not touched here, but it's the copied-literal bug class; worth one shared builder when any of them next changes.
- **Woodgrove's demo CA data was wrong** (8/10 invalid). Fixed; see [[Baseline Definitions & Mock Data]].

## Stage 2 : The CA evaluation engine (pure, heavily tested)

`src/lib/services/ca-policy-evaluator.ts`, importing only `../types` and small shared helpers. Modelled on Microsoft's own What If tool.

**Input: `SignInContext`**
`{ user (id, UPN, isGuest, adminRoles, group ids), targetResource ("Office365" | "AllResources" | appId | userAction), platform, deviceState ("compliant" | "hybridJoined" | "registered" | "unmanaged"), clientAppType ("browser" | "mobileAppsAndDesktopClients" | "exchangeActiveSync" | "other"), authenticationFlow? ("deviceCodeFlow" | "authenticationTransfer"), location (country, ipInTrustedLocation, ipInNamedLocationIds[]), signInRisk, userRisk, insiderRisk }`

**Output: `CaEvaluationResult`**
- `outcome`: `blocked` | `challenged` (allowed after satisfying controls, for example MFA) | `allowed` | `indeterminate`
- `enforcedPolicies[]` : each policy that applied, with the controls it requires
- `reportOnlyPolicies[]` : report-only policies that *would* have applied, and whether they would have blocked or challenged
- `trace[]` : one row per policy: applied, or *why not* (disabled, user excluded via group X, app not in scope, platform not matched, location trusted, risk condition not met, needs licence ...)
- `indeterminateReasons[]` : device filter present, nested group membership unknown, dynamic group, and so on

**Rules the engine must get right** (each one a table-driven test):
- A condition that is not configured matches everything; all configured conditions must match.
- Exclusions beat inclusions (users, groups, roles, guests, platforms, locations).
- Grant: any `block` wins; otherwise requirements combine according to `grantOperator`. `compliantDevice`, `domainJoinedDevice` or a phishing-resistant authentication strength that the context cannot satisfy means **blocked for that context**; `mfa` means **challenged**.
- Report-only policies never change the enforced outcome; they are listed separately.
- Risk conditions require Entra ID P2 (`hasEntraP2Capability()` from `entra-p2.ts`, never a new inline check); insider risk requires Purview Insider Risk Management. Without the licence, the policy is marked "unlicensed, would not evaluate", not "not matched".
- Security defaults on: evaluate the defaults' fixed behaviour (MFA registration and prompts for admins, legacy auth blocked) instead of CA.
- Group membership comes from `TenantGroup.members` (check whether that holds ids or UPNs before relying on it). Nested or dynamic groups give `indeterminate` rather than a guess.

**Fix recommender** (same module, pure): given a non-desired outcome, choose the most specific fix in this order:
1. A **report-only** policy would have produced the desired outcome: "Enable report-only policy *X*".
2. An enforced policy would have, but this user or context is **excluded**: "Remove the exclusion of *group Y* from *X*, or confirm it is a break-glass account".
3. A matching **CA0x baseline** exists ([[Baseline Definitions & Mock Data]]): "Deploy CA0x", deep-linked to [[Conditional Access Policy Scanner]]'s existing deploy flow.
4. Otherwise: "Create a new policy", with the concrete assignment, conditions and grant spelled out.

### Stage 2 build record (2026-09-29)
Built: `ca-policy-evaluator.ts`, `ca-sim-context.ts`, `ca-fix-recommender.ts`, each with tests (665 tests pass). Full description: [[CA Simulation Engine]].

**Stage 1 live verification, and what it found.** Nine tenants were synced. Only three got Stage 1 data, and within 30 minutes two of those three (Axiomatic, then Zubat Nine and Gustav Barkhuysen) had lost it again. Cause: the dev server had been running since 2026-09-28, and its background scheduler runs boot-time code, so it re-synced tenants with the old mapper and **overwrote** the new fields. Stage 1's code is correct (the three manual syncs proved every new field populates: extended policy fields on every policy, named locations resolving every policy reference, identity settings). **Action: `npm run restart`, then re-sync.**

Stage 1 follow-ups made during Stage 2:
- `UserMfaProfile.adminRoleTemplateIds`: the sync now keeps each role's template GUID. Live tenants hold many roles no hand-written map covers (Service Support Administrator, Groups Administrator, ...), and live CA policies target role GUIDs not in the map (3 found). Also: when only the MFA registration report says "admin", the sync writes a placeholder "Global Administrator" role name; the "Sign in as Global Admin" list relies on template ids, and flags name-derived entries as `inferred`.
- Token protection is now explicitly `false` when the beta read returned a policy without it. Before, "beta confirmed off" and "beta never ran" were both undefined.

Engine behaviours found live and now handled: a CA08 targeting app `"None"`; pre-Stage-1 policies evaluated as unknown (a device-code block had read as "block everything"); break-glass accounts being the first Global Admin in two tenants (the picker now flags them).

Notes for Stage 3: show a single tenant-level "re-sync needed" banner when `incompletePolicyIds` is non-empty, not per-policy reasons; flag `inferred` Global Admins and `breakGlassReasons` in the picker.

## Stage 3 : Sign-in Situations view

`SignInSituationsModule.tsx`, with the 26 situations defined as data in `src/lib/data/signin-situation-definitions.ts`: `{ id, persona, label, context overrides, desiredOutcome, rationale, docsUrl }`.

**"Sign in as" picker**
- **Admin accounts**: lists every Global Administrator from `mfaAudit` (`adminRoles` includes the Global Administrator name). Include other privileged roles behind a toggle, since CA admin policies usually target about 14 roles, not only GA.
- **Standard user**: searchable list of licensed, enabled, non-admin users.
- **Guest**: guests from `accountClassification.users`.
- **Foreign country**: country dropdown (reusing `sign-in-country.ts`, so names and flags match Sign-In Logs). It overrides the location of any "foreign country" situation and can also be applied to any persona.

**The 26 situations and their proposed desired outcomes** (for review):

| Persona | Situation | Desired outcome |
|---|---|---|
| Global Admin | Unmanaged device, known location | Blocked (compliant device required for admins) |
| Global Admin | Sign-in from a foreign country | Blocked |
| Global Admin | Sign-in from a hosting-provider address | Blocked or challenged with phishing-resistant MFA |
| Global Admin | Device-code flow | Blocked |
| Global Admin | Legacy authentication client | Blocked |
| Global Admin | High sign-in risk | Blocked or phishing-resistant MFA |
| Global Admin | Unmanaged macOS device | Blocked |
| Global Admin | Desktop client, unmanaged device | Blocked |
| Standard user | Unmanaged device, browser | Challenged (MFA), ideally with limited web access session control |
| Standard user | Sign-in from a foreign country | Blocked |
| Standard user | Device-code flow | Blocked |
| Standard user | Legacy Exchange ActiveSync | Blocked |
| Standard user | Other legacy client | Blocked |
| Standard user | High sign-in risk | Challenged (MFA) or blocked |
| Standard user | High user risk | Password change / risk remediation required |
| Standard user | Elevated insider risk | Blocked |
| Standard user | Unmanaged Android device | Blocked or app protection required |
| Standard user | Unmanaged iOS device | Blocked or app protection required |
| Standard user | Desktop client, unmanaged device | Blocked (compliant device required) |
| Guest | Browser access, known location | Challenged (MFA). This is a **good-path control case**: the expected result is allowed after MFA, so a "blocked" here is itself a finding |
| Guest | Sign-in from a foreign country | Blocked |
| Guest | Legacy authentication client | Blocked |
| Guest | Unmanaged device, browser | Challenged (MFA) |
| Guest | Device-code flow | Blocked |
| Guest | High sign-in risk | Blocked (guest risk is evaluated in the home tenant, so a note explains the limitation) |
| Guest | Authentication transfer | Blocked |

**Honest modelling notes to show in the UI:**
- **Hosting-provider addresses**: CA has no "hosting provider" condition. The simulation models it as "an IP outside every trusted named location" and says so. Microsoft's anonymous-IP risk detection *may* raise sign-in risk, but the engine does not assume it.
- **"Known location"** means inside a trusted named location. If the tenant has none, the situation shows grey with "no trusted locations defined".

**Result card per situation**
- Verdict chip: **Prevented** (green), **Not prevented** (red), **Partial** (amber), **Not assessed** (grey).
- Outcome line: "Blocked by *CA08: Block Access from Untrusted Countries*" / "Allowed after MFA by *CA02*" / "Allowed: no enforced policy applies because *user is excluded via group 'Travel Staff'* ...".
- "Would be blocked by report-only policy *X* if enabled", when applicable.
- Fix: from the Stage 2 recommender.
- Expandable **policy trace** (the per-policy table) so the reasoning can be checked.
- **Evidence from real sign-ins** (recommended extra): count matching real events in `snapshot.signIns`, for example "3 real sign-ins by Global Admins from foreign countries in the synced window". This turns a hypothetical into something observed.

Layout: persona and account picker on top, a summary strip ("19 of 26 prevented, 5 not prevented, 2 not assessed", clickable to filter, following the Sign-In Logs KPI-card convention), then the situation list.

### Stage 3 build record (2026-09-29)
Built: [[Sign-in Situations]] (module, situation definitions, runner, country list), wired into AppShell and a new **Security Simulations** sidebar group. 689 tests pass. Verified read-only against seven re-synced live tenants.

Changes to earlier stages made while building:
- **Engine:** risk-based policies don't apply to guests (Microsoft evaluates guest risk in the guest's home tenant); without this, "Guest · high sign-in risk" looked protected when it wasn't.
- **Fix recommender:** fixes that would also block the situation's normal twin are flagged "broad" and ranked last. Found live: "require a compliant device for everyone" was the answer to nearly every situation. Missing Entra ID P2 is its own first recommendation for risk situations.
- **Picker:** defaults to a typical account, not an individually excluded one (see the module note).
- **Demo data:** Woodgrove's CA09 now excludes guests (it blocked all guest collaboration, correctly flagged by the good-path situation); Contoso gained the `GuestServiceAccounts` group its CA02 excludes (it read "can't confirm" everywhere). `mock-tenants.test.ts` now guards that every `group:` marker resolves.
- **Tests:** `vitest.config.mjs` compiles JSX with Oxc so `.tsx` components can be imported, which enables the first component test.

Not done, and worth considering: a sidebar badge (red-situation count). Left out for now to keep the sidebar computation light; it would need the engine to run on every snapshot change.

## Stage 4 : CA Gap Analysis view

`CaGapAnalysisModule.tsx` plus a pure `ca-gap-analyzer.ts` built on the engine.

**Persona x control matrix** (matching the screenshot)
- Rows: Admins, Users, Guests, Workload identities.
- Columns: Multifactor authentication, Phishing-resistant authentication, Managed device, Legacy authentication blocked, Sign-in risk response, User risk response, Session limits, Location restrictions.
- Cell states: **Enforced** (green), **Report-only** (orange outline), **No policy** (red), **Unlicensed** (teal: risk columns without P2, workload identities without Workload ID Premium), **Not applicable** (dark: for example user risk for guests, managed device for workload identities).
- A cell is Enforced only if at least one enabled policy covers the **whole** persona for that control. A policy that covers "All users" but excludes a large group counts as partial, flagged in findings rather than silently green.
- Hover shows the policies behind the cell. **Clicking a red or orange cell opens Sign-in Situations preset to that persona and situation**, which ties the views together.

**Score out of 10.** Proposed, transparent formula (shown in a tooltip): weighted enforced cells divided by applicable, licensed cells, scaled to 10. Critical cells (admin MFA, admin phishing-resistant, legacy auth for everyone, user MFA) weigh double; report-only counts zero; not-applicable and unlicensed cells are left out. Subline: "17 of 21 controls enforced, 0 critical, 1 high findings". This is deliberately different from the existing CA baseline coverage score (CA01-CA10 match rate) in [[Conditional Access Policy Scanner]]; the UI should say which is which. *(Open question 5.)*

**Policy findings** (rules catalog in `src/lib/data/ca-gap-finding-rules.ts`, each with severity, source label, policies, fix text and a Microsoft Learn URL):
- Persona coverage gaps (one per red cell: "Admins have no enforced policy for Managed device").
- **Lockout risk**: an enforced block policy covering all users with no excluded emergency-access account. Critical, and the most important finding that is missing from the screenshot.
- Emergency-access accounts not excluded from every policy, or excluded accounts that are *not* break-glass (large groups, service accounts).
- Device registration not covered by a location or device policy (the screenshot's medium finding): no policy on the `urn:user:registerdevice` user action.
- Security info registration unprotected (`urn:user:registersecurityinfo`).
- Risk remediation with an authentication strength when an external authentication provider may be in use (the screenshot's high finding, shown as a precaution).
- Report-only policies older than 30 days (probably forgotten).
- Disabled policies, and policies referencing deleted users, groups or named locations.
- Legacy-auth block not scoped to all resources.
- Trusted named locations with very broad IP ranges.
- Security defaults on (CA not in use at all).

### Stage 4 build record (2026-09-30)
Built: [[CA Gap Analysis]] (analyzer, module, sidebar badge, links into Sign-in Situations). 711 tests pass. Verified read-only against all nine live tenants.

Decisions taken while building (open to review):
- The matrix uses synthetic persona users, so it answers "does policy cover this persona as a whole"; individual exclusions are findings, not cell colours.
- Report-only shows only when it would actually close the gap; otherwise the cell is red.
- Users × phishing-resistant is not applicable unless enforced (Microsoft recommends it for admins only); the reference screenshot shows it the same way.
- Workload identities are shown but not scored, because their licence can't be detected.
- The lockout finding counts MFA as "restricting", per Microsoft's emergency-access guidance, so an admin-MFA policy with no exclusion is flagged (high; critical when it blocks).

Earlier-stage changes: the Stage 1 mapper now accepts lower-case grant operators (Microsoft's own docs send `"and"`); the engine understands the newer `riskRemediation` grant; break-glass detection also judges against enforced policies only; `securityDefaultsPolicies()` is exported for the analyzer.

## Stage 5 : Extra data for the non-CA scenarios

| Data | Source | Used by |
|---|---|---|
| Unified audit log ingestion | EXO `Get-AdminAuditLogConfig` (`UnifiedAuditLogIngestionEnabled`) via `exo-client.ts` | Silent tenant |
| SMTP AUTH org-wide | EXO `Get-TransportConfig` (`SmtpClientAuthenticationDisabled`) | Legacy auth mailbox access |
| Per-mailbox POP/IMAP/EAS | EXO `Get-CASMailbox -ResultSize Unlimited` with only the protocol fields | Legacy auth mailbox access |
| Resharing and unmanaged sync | fields from the **already fetched** `admin/sharepoint/settings` (`isResharingByExternalUsersEnabled`, `isUnmanagedSyncAppForTenantRestricted`, sharing domain restrictions). Verify the field names live | Guest re-share, bulk sync |
| PIM eligible vs active assignments | `roleManagement/directory/roleEligibilityScheduleInstances` and `roleAssignmentScheduleInstances` (`RoleManagement.Read.Directory`, already held; needs P2) | Privilege escalation, mass deletion |
| OAuth delegated grants (optional) | `oauth2PermissionGrants` | Malicious OAuth consent (existing consented apps) |

EXO steps only run when EXO is connected. Otherwise the related checks show grey "Exchange not connected", never red or green. Also fix the stale in-memory EXO refresh token issue from [[Optimization Plan]]'s "Planned feature work" before adding more EXO steps to the sync, since each added EXO call raises its odds of surfacing.

### Stage 5 build record (2026-09-30)
Built, all pending one live sync to verify:
- **Stale EXO refresh token, fixed first** (as the plan required). `getExoAccessToken` now records every rotation old → new and forwards any holder of an older token in the chain to the newest; reconnecting Exchange (a token never rotated here) is never overridden. It also shares one in-flight refresh per tenant, closing a race where `fetchMailflowData`'s four parallel EXO calls could each redeem the same single-use token. `exo-client.ts`'s first tests.
- **SharePoint** (no extra call; same `admin/sharepoint/settings` response): resharing by guests, unmanaged-device sync restriction (+ allowed-domain count), sharing domain restriction mode, SharePoint legacy auth, idle session sign-out, invitee-must-match. **Found:** the existing mapper's default link type and Anyone-link expiry fields don't exist in v1.0, so those have always been placeholders on live tenants; `linkDefaultsReported: false` now says so.
- **Exchange** (only when EXO is connected): unified audit log ingestion (Microsoft: accurate only when read through Exchange Online, which is how Clarity365 reads it), org-wide SMTP AUTH, per-mailbox POP/IMAP/ActiveSync/SMTP AUTH (capped at 250 like the mailbox scan).
- **PIM:** eligible vs active (permanent / time-bound / activated) tenant-wide role assignments with principals; falls back to the non-PIM `roleAssignments` list (labelled `source: "roleAssignments"`) when PIM data isn't available (no P2).
- **OAuth consent grants:** `oauth2PermissionGrants` aggregated per app and consent type, with consenting-user counts, publisher verification, Microsoft-first-party flag and high-risk delegated scopes. Capped at 20 pages / 60 apps. Needs Directory.Read.All; otherwise "not assessed".
- Sync steps 22 → 25; **`SNAPSHOT_SYNC_SCHEMA_VERSION` bumped to 3**. Demo data for all four tenants (Woodgrove strict, Northwind the "silent tenant" with auditing off, Fabrikam without Exchange connected, Contoso mixed); demo refresh in `backfillSnapshot()` extended.

## Stage 6 : Scenarios view

`SecurityScenariosModule.tsx` plus `security-scenario-evaluator.ts`, with scenario definitions as data in `src/lib/data/security-scenario-definitions.ts`. Each scenario is a list of **checks** (defensive layers); each check returns prevented / not prevented / partial / not assessed, with evidence and a fix. A scenario's header shows "4 checks: 3 prevented, 1 not prevented", and each section header totals its scenarios.

**Identity & Conditional Access** (CA checks go through the Stage 2 engine)
- **Sign-in from outside allowed countries**: an enforced country-block policy for all users; no admin or guest exclusions; unknown countries included; country lookup method; device registration covered.
- **Stolen session token replay**: token protection session control; sign-in frequency for admins; compliant device required for admins; phishing-resistant MFA for admins; continuous access evaluation not disabled.
- **Guest account holding a directory role**: guests with any admin role (cross-referencing `mfaAudit` and `accountClassification`, data already present); guest user role restricted; guest MFA enforced.
- **Password spray on an account without MFA**: enabled users with no MFA registered; MFA policy covers all users with no gaps; legacy auth blocked (spray usually goes through it); list the exposed accounts.
- **Legacy authentication mailbox access**: CA01 enforced for all users; SMTP AUTH off org-wide; mailboxes with POP/IMAP/EAS still enabled.
- **Global admin on a non-compliant device**: an enforced admin policy requiring a compliant or hybrid-joined device; no GA excluded; Intune licensed.
- **Malicious OAuth app consent**: user consent disabled or limited to verified publishers; admin consent workflow enabled; existing apps with high-privilege permissions (existing `appRegistrations`).
- **Device-code phishing**: an authentication-flows policy blocking device code for all users, or at least admins.
- **Privilege escalation by role assignment**: number of permanent Global Admins (fewer than 2 or more than 5 is a finding); standing vs PIM-eligible; role-assignable groups with non-admin owners; apps holding `RoleManagement.ReadWrite.Directory`; admin MFA and phishing-resistant policies.

**Audit & Detection**
- **MFA tampering after compromise**: security info registration protected by CA; user-risk policy; unified audit log on; mailbox auditing on.
- **Silent tenant: auditing turned off**: unified audit log ingestion on; mailbox auditing on (existing `mailboxAuditingEnabled`); audit retention licence; sign-in log access working (no sign-in sync errors in `syncHealth`).
- **Mass user deletion**: standing User Admin / Global Admin count; PIM in use; protected actions via authentication context. Detection through alert policies cannot be read reliably, so that check shows as **manual verification** (grey with a checklist). Soft-deleted users are recoverable for 30 days, shown as information.

**Exchange & Email** (mostly existing data)
- **Mailbox rule exfiltration**: external forwarding rules found (existing `emailForwarding`); outbound anti-spam auto-forward blocked (existing MDO data); remote domain auto-forward blocked (existing); mailbox auditing on.
- **Transport-rule exfiltration**: transport rules redirecting or BCC'ing externally (existing `mailflowTransportRules`); Exchange admin count; unified audit log on.

**SharePoint & Data**
- **Bulk sync to an unmanaged device**: sync restricted to managed or domain-joined devices; a CA policy requiring a compliant device, or app-enforced restrictions, for SharePoint; unmanaged-device access policy.
- **Anyone link on a sensitive site**: tenant sharing level; sites allowing Anyone; Anyone-link expiry (existing). "Sensitive" needs a definition. *(Open question 6.)*
- **Guest re-share sprawl**: external resharing disabled; guest link expiry; sharing domain allow/deny list.

### Stage 5 live verification (2026-09-30)
Verified on the first sync: Exchange audit/protocol data on the two Exchange-connected tenants, SharePoint settings everywhere, schema version 3. Two fixes followed:
- **PIM fell back to the non-PIM list on every tenant**, P2 or not. Dropped `$expand=principal` from the PIM schedule calls (principals are now resolved from already-synced users and groups) and recorded `pimUnavailableReason` when PIM still isn't available. **Needs one more sync to confirm.**
- **OAuth grants failed on every tenant with "Insufficient privileges"** (the app registrations have Organization.Read.All, not Directory.Read.All), and the sync error marked every tenant degraded. Now recorded as `unavailable: "missingPermission"` without a sync error, and **"DelegatedPermissionGrant.Read.All / Directory.Read.All" was added as an optional row in the Permissions check** so the gap is visible and fixable.

### Stage 6 build record (2026-09-30)
Built: [[Security Scenarios]] (17 scenarios, 4 sections), wired as the first entry of the Security Simulations sidebar group with a red-scenario badge. 743 tests pass; verified read-only against 11 tenants. Also changed during this stage: the engine's partial-resource coverage and synthetic-user group membership (see the module note), and the stricter verdict roll-up (red if any check is not prevented).

**For review:** with the strict roll-up, 10-16 of 17 scenarios are red on real tenants, largely from checks few tenants pass yet (token protection, device-registration policy, protected actions, manual alert checks). Alternatives if that's too stark: weight checks (core vs hardening), or make hardening-only gaps orange.

## Stage 7 : Integration and polish (optional, pick and choose)

- Sidebar: a new **Security Simulations** group in the per-tenant section (after Identity & Access) with three entries, `sim_scenarios`, `sim_signin` and `sim_ca_gaps`; badge = count of red scenarios.
- CSV and PDF export of each view (reuse `csv.ts` and the report modal).
- Read-only MCP tools `simulate_signin` and `get_ca_gap_analysis` in [[MCP Server]].
- Add the CA score and top findings to [[Executive Reporting (QBR)]].
- **Break-glass designation**: let the operator mark one tenant's emergency-access accounts, so their exclusions read as intended rather than as gaps. This is a tenant-scoped settings write through [[Tenant Store]]. *(Open question 3.)*
- **Live What If cross-check**: Microsoft Graph has a Conditional Access What If evaluation API in **beta** (`POST /identity/conditionalAccess/evaluate`). **Unverified: confirm on Microsoft Learn before building.** If it exists, a "verify with Microsoft" button per situation would give ground truth (including nested groups and device filters the local engine marks indeterminate) through a read-only, single-tenant route. The local engine stays primary, because it works for demo tenants, offline, and explains *why*.

## Final item (after all Security Simulations work) : pre-existing lint errors

**Done 2026-09-30** (brought forward at the user's request, ahead of Stage 7). All 33 `react/no-unescaped-entities` errors escaped (`&apos;` / `&quot;`, by exact lint position). The three hook warnings were each reviewed rather than silenced: Defender Config's `onboardingStates` fallback is now memoized; Fleet Baseline Rollout's `getTenantBaselineStatus` is a `useCallback` on `snapshotMap` (it already only read that, so no behaviour change); MCP Playground's effect uses a functional state update. **Adding `selectedTenantId` to that effect's dependencies, as lint suggested, would have been a bug** - it would snap a manually picked tenant back to the current one. Result: `next lint` clean across `src`, and **`next build` succeeds** (verified on a scratch copy so the running dev server's `.next` wasn't touched). 743 tests pass.

Original booking:
Booked 2026-09-30 at the user's request, to do once every stage above is finished. **Scope corrected the same day:** the first count (2 errors in `IntuneSecurityModule.tsx`) came from a lint run piped through `tail`, which hid all but the last file. The real state of `npx next lint --dir src`: **33 errors, all `react/no-unescaped-entities`** (unescaped `'` / `"` in JSX text), plus 3 `react-hooks/exhaustive-deps` warnings, in 8 files that predate this feature:

| File | Errors | Warnings |
|---|---|---|
| `modules/DefenderConfigurationModule.tsx` | 13 | 1 |
| `modules/AsrRulesModule.tsx` | 6 | |
| `modules/ComplianceMatrixModule.tsx` | 4 | |
| `modals/ReportPreviewModal.tsx` | 3 | |
| `modules/ConditionalAccessModule.tsx` | 2 | |
| `modules/DataProtectionModule.tsx` | 2 | |
| `modules/IntuneSecurityModule.tsx` | 2 | |
| `modules/FleetDataProtectionModule.tsx` | 1 | |
| `modules/FleetBaselineRolloutModule.tsx` | | 1 |
| `modules/McpPlaygroundModule.tsx` | | 1 |

**Why it matters more than it looks:** `next.config.mjs` doesn't set `eslint.ignoreDuringBuilds`, so `next build` runs lint and fails on errors. `npm run build` (and so the Docker image) is broken until these are fixed; `npm run dev` is unaffected. The fix is mechanical (escape the characters; review each hook-dependency warning rather than blindly adding dependencies), then confirm `next lint` is clean and `next build` succeeds (with the dev server stopped, since both use `.next/`).

## Files and blast radius

| Area | Files | Notes |
|---|---|---|
| Hub files | `types/index.ts`, `graph-client.ts`, `exo-client.ts` | Stages 1 and 5 only; optional fields only |
| New pure services | `ca-policy-evaluator.ts`, `ca-gap-analyzer.ts`, `security-scenario-evaluator.ts`, `directory-role-templates.ts`, each with a `.test.ts` | |
| New data catalogs | `signin-situation-definitions.ts`, `ca-gap-finding-rules.ts`, `security-scenario-definitions.ts` | |
| UI | three modules; `AppShell.tsx` (3 `activeView`s); `Sidebar.tsx` (new group) | |
| Demo data | `mock-tenants.ts` (all four tenants) | |
| Vault | new module notes for each view; [[Core Graph Layer]], [[Domain Types]], [[Data Mappers]], [[AppShell]], this plan, [[Clarity365 MOC]] | Same session as each stage |

## Open questions for review

1. **Verdict colours**: green and red only, or add **amber (partial)** and **grey (not assessed)**? Recommended: all four, so missing data never shows green.
2. **Desired outcomes**: review the per-situation table in Stage 3. In particular, should "allowed after MFA" count as prevented for foreign-country sign-ins, or must those be blocked?
3. **Break-glass accounts**: add a per-tenant "emergency-access accounts" setting (Stage 7), or infer them (for example accounts excluded from every policy)? Recommended: explicit setting, with inference only as a suggestion.
4. **Fix actions**: read-only recommendations with deep links to the existing CA deploy flow (recommended for the first release), or add "deploy this as report-only" buttons later?
5. **Score**: is the proposed weighted formula acceptable, and should the CA baseline score in the existing CA module stay separate?
6. **"Sensitive site"**: until sensitivity labels exist (see [[Sensitivity Labels Catalog Plan]]), use an operator-maintained list of sensitive sites, a name heuristic, or treat every site as sensitive?
7. **Build order**: agree to engine, then Sign-in Situations, then CA Gap Analysis, then Scenarios?
8. **Live What If**: worth investigating the Graph beta API in Stage 7, or keep everything local?

Part of [[Clarity365 MOC]]. See also [[Optimization Plan]], [[Conditional Access Policy Scanner]], [[Sign-In Logs & CA Diagnostics]].
