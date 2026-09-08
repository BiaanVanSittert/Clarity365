---
tags: [service]
---

# Core Graph Layer

The Microsoft Graph / Exchange Online integration layer. Four files:

## graph-client.ts :  the master orchestrator
~1230 lines. `fetchLiveTenantSnapshot` is the one function that, on a tenant sync, pulls CA policies, users, directory roles, sign-ins, MFA, Intune, Secure Score, MDO + mailflow (via `exo-client`), domain auth, groups, SharePoint, app registrations, SKUs, and incidents :  then hands the result to every [[Data Mappers|mapper]] and [[Baseline Matchers|matcher]] to assemble one `TenantSecuritySnapshot` (see [[Domain Types]]). Also exports `getGraphAccessToken`, `testAppRegistrationPermissions`, `buildGraphCaPolicyPayload`, `deployConditionalAccessPolicy`.
**No test file** :  the largest, most critical, most fan-out file in the codebase is untested. See [[Testing]].
Also resolves per-user `assignedLicenses` `skuId` GUIDs to `skuPartNumber` names (e.g. `"SPE_E5"`) using the tenant-wide `subscribedSkus` fetch, right after that fetch completes :  a post-processing remap of `usersList`, not a reordering of the sync. Required for [[Data Mappers]]'s `admin-hygiene-matcher` to recognize licenses on live tenants (mock data already uses friendly names).

CA policy mapping now carries through `conditions.locations`, `conditions.platforms`, `conditions.userRiskLevels`, `conditions.signInRiskLevels`, and `conditions.users.includeRoles` from the raw Graph response :  these were silently dropped before, which broke CA06/CA07/CA08's (and admin-role-targeted CA03/CA10's) re-validation against the stored snapshot on live tenants even though the initial sync-time classification was correct. `grantControls.authenticationStrength` (a sibling of `builtInControls`, not part of it) is encoded as an `"authenticationStrength:<name>"` marker string appended to the `grantControls` array, matching this app's own convention (see [[Baseline Matchers]]'s `hasAuthStrengthOrSession`). Also fixed: the `RoleManagement.Read.Directory` permission-test endpoint used `?$top=1`, which Graph's `/directoryRoles` doesn't support (`HTTP 400`) :  reported as a missing permission regardless of what was actually granted.

## exo-client.ts :  Exchange Online
OAuth device-code flow + `invokeExoCommand`, `fetchMdoPoliciesAndTabl`, `fetchMailflowData`, `fetchAcceptedDomainsAndDkim`, TABL writes, `disableForwardingRule`, `removeMailboxDelegation`, `setMailboxAuditingEnabled`.
**No test file** :  handles live EXO writes and the device-code auth flow. See [[Testing]].

## graph-fetch.ts
`graphFetch` :  retry/backoff HTTP wrapper. No local imports (leaf). Used by graph-client, graph-pagination, exo-client, and [[Tenant Store]] directly. Has a test.

## graph-pagination.ts
`fetchAllPages`. Imports graph-fetch. Has a test.

Part of [[Clarity365 MOC]]. Downstream consumer: [[Tenant Store]] (`syncTenant`).
