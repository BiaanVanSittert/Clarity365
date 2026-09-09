---
tags: [service]
---

# Core Graph Layer

The Microsoft Graph / Exchange Online integration layer. Four files:

## graph-client.ts :  the master orchestrator
~1230 lines. `fetchLiveTenantSnapshot` is the one function that, on a tenant sync, pulls CA policies, users, directory roles, sign-ins, MFA, Intune, Secure Score, MDO + mailflow (via `exo-client`), domain auth, groups, SharePoint, app registrations, SKUs, ASR rule configuration state (three merged Intune surfaces - see [[Attack Surface Reduction Rules]]), and incidents :  then hands the result to every [[Data Mappers|mapper]] and [[Baseline Matchers|matcher]] to assemble one `TenantSecuritySnapshot` (see [[Domain Types]]). Also exports `getGraphAccessToken`, `testAppRegistrationPermissions`, `buildGraphCaPolicyPayload`, `deployConditionalAccessPolicy`.

`testAppRegistrationPermissions`' self-test loop supports a per-permission `method`/`body` override (defaulting to plain GET) so a permission with no GET-able Graph surface can still be tested - `ThreatHunting.Read.All` (Advanced Hunting is POST-only) is the one permission that needs this today. Every tested permission carries an `optional` flag, excluded from the pass/fail rollup, so declining an optional permission (currently: this one, plus the CA write permission) never shows as a problem.

Also exports `fetchAsrDetectionSummaries`/`fetchAsrDetectionEvents` for [[Attack Surface Reduction Rules]] - notably **not** called from `fetchLiveTenantSnapshot`, the one pair of Graph functions in this file deliberately kept out of the main sync (on-demand only, since `security/runHuntingQuery` needs the separate `ThreatHunting.Read.All` permission + a Defender for Endpoint P2 license many tenants won't have consented to, and would slow down every sync for one module's data otherwise). Both follow `deployConditionalAccessPolicy`'s mock-short-circuit-first shape; the live path shares an internal `runHuntingQuery()` helper that POSTs to `v1.0/security/runHuntingQuery` (not beta) and normalizes Graph's camelCase result rows.
**No test file** :  the largest, most critical, most fan-out file in the codebase is untested. See [[Testing]].
Also resolves per-user `assignedLicenses` `skuId` GUIDs to `skuPartNumber` names (e.g. `"SPE_E5"`) using the tenant-wide `subscribedSkus` fetch, right after that fetch completes :  a post-processing remap of `usersList`, not a reordering of the sync. Required for [[Data Mappers]]'s `admin-hygiene-matcher` to recognize licenses on live tenants (mock data already uses friendly names).

CA policy mapping now carries through `conditions.locations`, `conditions.platforms`, `conditions.userRiskLevels`, `conditions.signInRiskLevels`, and `conditions.users.includeRoles` from the raw Graph response :  these were silently dropped before, which broke CA06/CA07/CA08's (and admin-role-targeted CA03/CA10's) re-validation against the stored snapshot on live tenants even though the initial sync-time classification was correct. `grantControls.authenticationStrength` (a sibling of `builtInControls`, not part of it) is encoded as an `"authenticationStrength:<name>"` marker string appended to the `grantControls` array, matching this app's own convention (see [[Baseline Matchers]]'s `hasAuthStrengthOrSession`). Also fixed: the `RoleManagement.Read.Directory` permission-test endpoint used `?$top=1`, which Graph's `/directoryRoles` doesn't support (`HTTP 400`) :  reported as a missing permission regardless of what was actually granted.

Also fixed: the `/users` fetch now selects `signInActivity`, whose `lastSignInDateTime` is Graph's authoritative "last interactive sign-in" (requires `AuditLog.Read.All`, already held for `auditLogs/signIns`). The MFA-profile mapping previously hardcoded `lastSignInDateTime: new Date().toISOString()` as a fallback :  every user, including ones who had never signed in, showed "Today" in [[Tenant License Optimization]] and [[Fleet License Optimization]]. Now it prefers the real `signInActivity` value, falls back to the most recent matching `auditLogs/signIns` event, and finally `""` (never signed in) :  never the current timestamp.

The `/subscribedSkus` fetch (used for `capabilitiesLive` and the `skuId -> skuPartNumber` map) now also builds `licenseSkusLive: TenantLicenseSku[]` (`consumedUnits`, `prepaidUnits.enabled`, and the derived `availableUnits` gap) and assigns it to `base.licenseSkus`. This is what [[Analysis & Generation]]'s `calculateTenantMonthlyWaste` prices out as the `unassigned_license_sku` waste category :  previously the type/summary plumbing existed end-to-end but no code ever populated it, so purchased-and-unassigned seats never appeared anywhere in the license optimizer.

## exo-client.ts :  Exchange Online
OAuth device-code flow + `invokeExoCommand`, `fetchMdoPoliciesAndTabl`, `fetchMailflowData`, `fetchAcceptedDomainsAndDkim`, TABL writes, `disableForwardingRule`, `removeMailboxDelegation`, `setMailboxAuditingEnabled`.
**No test file** :  handles live EXO writes and the device-code auth flow. See [[Testing]].

## graph-fetch.ts
`graphFetch` :  retry/backoff HTTP wrapper. No local imports (leaf). Used by graph-client, graph-pagination, exo-client, and [[Tenant Store]] directly. Has a test.

## graph-pagination.ts
`fetchAllPages`. Imports graph-fetch. Has a test.

Part of [[Clarity365 MOC]]. Downstream consumer: [[Tenant Store]] (`syncTenant`).
