---
tags: [optimization, plan, data-protection]
---

# DLP Stage 1: Data Model, Licensing, Sync, Mocks

In-depth plan for Stage 1 of [[DLP & Sensitivity Labels Plan]]. Status: **planning only**. Everything here is grounded in code read on 2026-09-21; anything that depends on Purview's real behaviour is marked **(verify in Stage 0)** and must not be built from assumption.

## Goal
Get real Purview data (labels, label policies, DLP policies and rules, auto-labeling policies, sensitive information types) into `TenantSecuritySnapshot` reliably, with correct licence gating, safe handling of old data, and honest failure states. **No UI, no baselines, no writes.** Stage 2 builds on this and Stage 3 needs the licence and SIT data.

## Decisions (2026-09-21)
1. `TenantSecuritySnapshot.dataProtection` stays **optional** in the type.
2. **Purview gets its own connect step**, separate from "Connect Exchange Online". Consequences, folded into the sections below: a separate `credentials.purviewRefreshToken?` (encrypted, masked, rotated exactly like `exoRefreshToken`), its own device-code start and poll routes, and its own step in `PermissionsModal.tsx`. "Not connected" for the Purview sections now means `purviewRefreshToken` is unset, independent of Exchange. This also removes the cross-resource refresh-token coupling described in 1.4.
3. **Test tenant: Crimson Line Live Demo** (`tenant-mtsmi5hr`). Verified 2026-09-21, see the next section.

## Test tenant verification: Crimson Line Live Demo
Checked read-only against Microsoft Graph `/subscribedSkus` using the tenant's stored app credentials (no Exchange refresh token touched):
- The only paid SKU is `DEVELOPERPACK_E5` (Microsoft 365 E5 developer subscription), 25 seats, 18 consumed, `capabilityStatus: Enabled`.
- Its service plans all report `Success` for the Purview features Stage 1 needs: `MIP_S_CLP1`, `MIP_S_CLP2` (sensitivity labels, auto-labeling), `MIP_S_Exchange`, `RMS_S_PREMIUM`, `RMS_S_PREMIUM2`, `RMS_S_ENTERPRISE` (encryption), `COMMUNICATIONS_DLP` (Teams DLP), `ML_CLASSIFICATION` (trainable classifiers), `Content_Explorer`, `INSIDER_RISK`, `M365_ADVANCED_AUDITING`, `EQUIVIO_ANALYTICS`, plus `ATP_ENTERPRISE` and `AAD_PREMIUM_P2`. Service-plan names recalled during planning (`MIP_S_CLP1`, `MIP_S_CLP2`, `RMS_S_*`, `COMMUNICATIONS_DLP`) were correct for this SKU.
- **No Endpoint DLP plan appeared**, so Endpoint DLP cannot be tested on this tenant (plan name not independently confirmed).
- The app registration has **no** information-protection Graph app roles, as expected. Only relevant if Stage 0 tests the Graph label endpoints.
- An Exchange Online delegated connection exists (`exoRefreshToken` set, MDO policies and 20 mailboxes synced), so a delegated flow has worked here before. There is no Purview connection yet.
- Sync is currently `degraded` for unrelated reasons (sign-in logs timeout, app registrations and security-incident permissions, MDE connector scope). None concern Purview, but the sync-health interplay in 1.6 should be re-checked against this tenant.

**Not verified yet:** that the compliance endpoint accepts a delegated token here, which role the connecting admin holds, whether any labels or DLP policies already exist (an empty tenant tests the "none configured" path but not the mappers), and whether the developer subscription is still within its renewal window.

**This tenant is also a live example of the licensing gap**: the app's stored capabilities for it read `cap-purview` unlicensed, and also `cap-mdo`, `cap-mde` and `cap-intune` unlicensed, because `DEVELOPERPACK_E5` matches none of the SKU-name substrings. Stage 1's service-plan-based entitlements fix this class of miss (see 1.2).

## Prerequisites from Stage 0
Stage 1 cannot start until Stage 0 delivers:
- Redacted real JSON output for each cmdlet in the sync (fixtures for every mapper test).
- Confirmation the compliance endpoint accepts the existing delegated refresh token, and the exact resource scope and URL.
- The role or roles the connecting admin needs, and whether extra consent is needed at device-code time.
- Whether a redeemed refresh token is really single-use (the code comment in `exo-client.ts` says so; Microsoft's own behaviour may be looser).
- Real error text for "unlicensed", "no role", "not connected", and a transient failure.

## Design principles (each traces to a recorded bug class in [[Optimization Plan]])

| Principle | Why |
|---|---|
| A section that was never fetched, is unlicensed, is not connected, or failed must not look like "nothing configured" | The ASR module showed every rule "Not Configured" on live tenants because the live half was never built. A false "no DLP policy" finding is the same bug. |
| Entitlements come from live licence evidence, tri-state (`entitled`, `not_entitled`, `unknown`) | `createBlankSnapshot()` seeds capabilities as `licensed: true` placeholders, so a blank snapshot lies. |
| Licence checks are one shared pure function, verified against what the live mapper emits | Mock tenants use `cap-purview-e5`; live only emits `cap-purview`. Same class as Entra P2 and MDE. |
| Match on GUIDs (label, policy, SIT), never display names | Microsoft's ASR displayName change broke matching tenant-wide. Admins can also rename labels and policies. |
| Any literal value (SIT GUID, mode enum, workload name) is defined once and imported | The CA01 `otherClients` value was copy-pasted into nine places and every copy agreed. |
| New required snapshot fields must survive old persisted data | `SecureScoreControl.deployment` crashed a whole module for a tenant synced before the field existed. |
| Preserve last-good data on a transient failure, per section | Existing convention (`asrRulesLive !== null`). |

## 1.1 Types (`src/lib/types/index.ts`)
`types/index.ts` is a hub file (1550 lines, imported everywhere). Changes must be **additive and optional only**. Check its note in [[Domain Types]] and the incoming links before editing.

Add:

```ts
export type DataProtectionSectionKey =
  "labels" | "labelPolicies" | "autoLabelPolicies" | "dlp" | "sensitiveInfoTypes";

export type DataProtectionSectionStatus =
  | "not_fetched"    // never attempted (blank snapshot, or pre-feature data)
  | "ok"
  | "not_connected"  // Exchange/Purview delegated connection missing
  | "unlicensed"     // tenant verifiably lacks the entitlement
  | "error";         // attempted and failed; items are last-good, if any

export interface DataProtectionSectionState {
  status: DataProtectionSectionStatus;
  fetchedAt?: string;   // last attempt
  lastGoodAt?: string;  // last time status was "ok"
  error?: string;       // raw or cleaned message, only for "error"
}

export interface DataProtectionSnapshot {
  sections: Record<DataProtectionSectionKey, DataProtectionSectionState>;
  labels: SensitivityLabel[];
  labelPolicies: LabelPolicy[];
  autoLabelPolicies: AutoLabelPolicy[];
  dlpPolicies: DlpPolicy[];          // each carries its rules
  sensitiveInfoTypes: SensitiveInfoTypeRef[];
}
```

Domain shapes (field names below are **proposals, verify against Stage 0 fixtures**):
- `SensitivityLabel`: `id` (GUID), `name`, `displayName`, `parentId?`, `priority`, `isActive`, `contentScopes` (file/email, site/group, schematized data), `encryption` (`enabled`, kind), `hasMarking`, `hasAutoLabeling`.
- `LabelPolicy`: `id`, `name`, `labelIds[]`, `targets` (users/groups/locations), `defaultLabelId?`, `mandatoryLabeling`, `requireDowngradeJustification`, `enabled`, `distributionStatus?`.
- `AutoLabelPolicy`: `id`, `name`, `targetLabelId`, `mode`, `locations`, `sitIds[]`.
- `DlpPolicy`: `id`, `name`, `mode` (`Enable | TestWithNotifications | TestWithoutNotifications | Disable | unknown`), `enabled`, `locations` (exchange, sharePoint, oneDrive, teams, endpoint, thirdPartyApps; each `all | none | scoped`), `priority`, `whenChanged`, `rules: DlpRule[]`.
- `DlpRule`: `id`, `name`, `disabled`, `priority`, `sitConditions[]` (`sitId`, `minCount`, `maxCount?`, `minConfidence`), `labelConditionIds[]`, `groupOperator?`, and the actions (`blockAccess`, `blockScope`, `notifyUser`, `generateIncidentReport`, `overrideAllowed`, `encryptOnSend`). The SIT-condition property is a **nested, grouped structure** in the real cmdlet output. It is the highest-risk mapping in Stage 1.
- `SensitiveInfoTypeRef`: `id`, `name`, `isCustom`. Store only the SITs referenced by the Stage 3 catalog plus every custom SIT. The full built-in list is several hundred entries and does not need to live in every snapshot.

Optionality decision: `TenantSecuritySnapshot.dataProtection?: DataProtectionSnapshot` (optional in the type), always populated by backfill on read and always accessed through `normalizeDataProtection()`. Reason: a required field would force edits to every test fixture that builds a full snapshot. Newer fields such as `asrRules?` and `licenseSkus?` already follow this convention.

Also add `servicePlans?: { name: string; provisioningStatus: string }[]` to `TenantLicenseSku` (see 1.2).

Also add one audit category for Stage 4 later (`AuditLogEntry.category`); not needed in Stage 1.

## 1.2 Licensing and entitlements

### What exists
- `capabilities-mapper.ts:68`: `hasPurview = hasSku(["ADVANCED_AUDITING","COMPLIANCE","INFORMATION_PROTECTION","SPE_E5"])`, emitted as one generic `cap-purview` whose tier is "Active" or "Standard". No consumer of `cap-purview` exists outside the mapper and mock fixtures (grep), so it can be changed safely, but should not be repurposed: E3 and Business Premium would still read as "Standard".
- `mapSubscribedSkusToCapabilities` matches SKU part-number substrings. `/subscribedSkus` also returns `servicePlans` for every SKU; **the current sync discards them** (no `servicePlans` reference anywhere in `src`).
- `isBusinessPremiumSku()` already handles the `O365_BUSINESS_PREMIUM` naming trap and must be reused, not re-derived.
- `Tenant.tier` (`M365_E5 | M365_E3 | M365_BP | M365_F3 | A5_EDU`) is a user-set label, not evidence.

### Approach
Capture **service plans** during the existing step 16 SKU fetch (no extra API call), then derive entitlements from service plans first and SKU part numbers second. Service plans are the correct granularity because SKU names are brittle across bundles, add-ons, EDU and F-series. Initial service-plan names to investigate (from memory, **verify against Microsoft's "product names and service plan identifiers" reference in Stage 0**): `MIP_S_CLP1`, `MIP_S_CLP2`, `RMS_S_PREMIUM`, `RMS_S_ENTERPRISE`, `COMMUNICATIONS_DLP`.

New pure module `src/lib/utils/data-protection-license.ts` (beside `entra-p2.ts`):

```ts
export type Entitlement = "entitled" | "not_entitled" | "unknown";

export interface DataProtectionEntitlements {
  dlpCore: Entitlement;         // Exchange, SharePoint, OneDrive DLP
  manualLabels: Entitlement;
  teamsDlp: Entitlement;
  endpointDlp: Entitlement;
  autoLabeling: Entitlement;
  trainableClassifiers: Entitlement;
  exactDataMatch: Entitlement;
  containerLabels: Entitlement; // depends on Entra ID P1 as well
}

export function getDataProtectionEntitlements(snapshot: TenantSecuritySnapshot): DataProtectionEntitlements;
```

Rules:
- Return `unknown` for everything unless live licence evidence exists (`licenseSkus` present). Never trust the blank snapshot's placeholder capabilities.
- Service plans (when present) decide; SKU part numbers decide when service plans are absent (old snapshots synced before this change); the entitlement table lives in one exported constant with a "last verified" date and a source comment per row.
- Demo tenants: give the four mock tenants **live-shaped** licence data (`licenseSkus` with service plans), not tier-specific capability ids, so mock and live go through the same code path.
- Reuse `isBusinessPremiumSku`; export any new helper from `capabilities-mapper.ts` rather than duplicating SKU lists.
- Also emit a generic capability from the mapper (a `cap-dataprotection` entry, tier-distinguished by its `tier` string) so the existing Capabilities UI shows something accurate. Do **not** remove `cap-purview` (audit-log retention semantics stay as is).

### Parity test (the regression for the recurring bug class)
For each tenant archetype (E5, E3, Business Premium, F3, A5 EDU, an add-on-only tenant), build the snapshot two ways, once as a mock fixture and once by running the same SKUs through `mapSubscribedSkusToCapabilities`, then assert `getDataProtectionEntitlements()` returns identical output.

## 1.3 Snapshot scaffolding and migration

- `createBlankSnapshot()` (`src/lib/data/default-snapshot.ts`): add `dataProtection: createBlankDataProtection()` with every section `not_fetched` and empty arrays.
- `backfillSnapshot()` in `tenant-store.ts` does `{...blank, ...snapshot}`, so a missing top-level `dataProtection` is filled automatically. It does **not** deep-merge, and a partially present `dataProtection` (for example a later-added section key) would stay partial. To avoid growing `tenant-store.ts` and to make this testable, put the merge in a pure exported `backfillDataProtection(blank, existing)` in the mapper file, and have `backfillSnapshot()` call it in one line.
- Add `dataProtection` to the `isDemo` "prefer current `mock-tenants.ts`" field list in `backfillSnapshot()`. Without it, editing mock data has no effect on already-seeded demo tenants (the `signIns` lesson, recorded in [[Tenant Store]]).
- `normalizeDataProtection(snapshot.dataProtection)` is the single access path for every consumer (Stage 2 module, `fleet-analyzer`, MCP tools). It returns a fully populated object even for `undefined`.
- Regression test: a JSON blob from a pre-feature snapshot (no `dataProtection`) must load, normalize, and round-trip without a crash.

## 1.4 Purview client (`src/lib/services/purview-client.ts`, new)

Kept out of `exo-client.ts`, which is untested, live-write-capable and already large. Read-only in Stage 1.

### The refresh-token hazard (found by reading the code, must be designed around)
`getExoAccessToken()` redeems `credentials.exoRefreshToken` with a fixed Exchange scope and caches the access token for about 55 minutes. When Microsoft rotates the refresh token, the callback persists the new one to SQLite, but **the in-flight `tenant` object passed through `fetchLiveTenantSnapshot` is never updated** (graph-client.ts passes `tenant` and `onExoRefreshRotated` straight through, lines 2776, 2826, 2860). Today that is hidden: step 9 rotates, and steps 11 and 12 hit the token cache. A Purview call needs a token for a **different resource**, so it is a cache miss and would redeem the **stale** refresh token from the in-memory object. Depending on Microsoft's real behaviour (Stage 0), that either fails or silently breaks the stored connection.

Design:
- **Superseded in part by decision 2 (own connect step):** Purview gets its own `purviewRefreshToken`, so a Purview call never redeems the Exchange token and the two cannot invalidate each other. What remains is the same latent problem, per token.
- In `fetchLiveTenantSnapshot`, wrap **both** rotation callbacks so each also updates a local tenant copy (`exoTenant`, `purviewTenant`) passed to every step that uses that token. This fixes the latent case where a long sync outlives the 55-minute cache.
- Persist through a new `persistPurviewRefreshToken()` beside `persistExoRefreshToken()`; the purview token cache key includes the resource (`purview:${tenantId}`).
- If Stage 0 finds the compliance resource cannot be reached with its own device-code token, this design needs to be revisited before any code is written.
- Log the EXO half in [[Optimization Plan]] as a found gap regardless of whether the feature ships (done).

**Purview connect step (new work implied by decision 2):**
- `Tenant.credentials.purviewRefreshToken?` in `types/index.ts`.
- `tenant-store.ts`: encrypt, mask (`SECRET_MASK`), decrypt and persist handling, mirroring the three existing `exoRefreshToken` sites (roughly lines 538 to 592).
- Routes `POST /api/tenants/[id]/purview-connect/start` and `.../poll`, mirroring `exo-connect/start` and `.../poll`, using the compliance resource scope (**verify**).
- `PermissionsModal.tsx`: a separate "Connect Microsoft Purview" step and status row. See [[Modals]].
- Same public client and device-code pattern as Exchange, so no new app-registration configuration is expected. Stage 0 confirms.

### Functions
- `getComplianceAccessToken(credentials, onRotated)`: refresh-token grant with the compliance resource scope **(verify)**.
- `invokeComplianceCommand(tenant, cmdlet, params, onRotated)`: same shape as `invokeExoCommand`, compliance endpoint **(verify URL)**, 30 s per-call timeout via the existing `graphFetch`, same array-or-`.value` response normalization plus any paging the endpoint needs **(verify)**.
- `classifyPurviewError(rawText)` returns `"unlicensed" | "no_role" | "not_connected" | "transient" | "unknown"`. Tested with **captured real text**. Defaults to `unknown` with the raw message; it must never confidently name a cause it has not matched (the ASR "Defender for Business lacks this table" correction is the reason).
- Fetchers: `fetchLabels`, `fetchLabelPolicies`, `fetchAutoLabelPolicies`, `fetchDlpPolicies` (policies plus rules; single rules call versus one call per policy is a Stage 0 question), `fetchSensitiveInfoTypes`. Each returns `{ items, error? }` and never throws.
- `testPurviewConnectivity(tenant)`: the minimum-surface probe (one cheap cmdlet) that distinguishes not connected, no role, unlicensed, and endpoint error. Kept minimal so a failure cannot be misattributed (the `ThreatHunting.Read.All` probe lesson). Surfaced in the UI in Stage 2, exposed alongside `testExoConnectivity`.

## 1.5 Mappers (`src/lib/services/data-protection-mapper.ts`, new, pure)
`mapSensitivityLabel`, `mapLabelPolicy`, `mapAutoLabelPolicy`, `mapDlpPolicy`, `mapDlpRule`, `mapSensitiveInfoType`, `normalizeDataProtection`, `backfillDataProtection`, `summarizeDataProtection` (counts, reused later by a Sidebar badge so the badge and the module cannot disagree, as with `defenderCoverageGapCount`).

Rules:
- Built from Stage 0 fixtures only. Unknown enum values map to an explicit `"unknown"`, never to a default that reads as safe (an unrecognized DLP mode must not be treated as `Enable`).
- Every ID is the GUID from the cmdlet output, and every reference between objects (rule to SIT, policy to label) is by GUID.
- The nested SIT-condition parser needs the most test cases: a single SIT, multiple SITs with AND, grouped OR, a label-based condition, and an empty condition.
- Defensive against absent fields; never throws on a malformed row (skip and count it in a `mappingWarnings` string surfaced as a section error).

## 1.6 Sync integration
Extract the orchestration into its own file so it is testable (the sync itself is untested today):

`src/lib/services/data-protection-sync.ts`: `runDataProtectionSync({ tenant, entitlements, existing, onRotated, onProgress })` returns `{ dataProtection, syncErrors }`. `graph-client.ts` makes one call to it.

Steps and progress: add three progress steps after step 19, so `TOTAL_SYNC_STEPS` goes 19 to 22 (only `tenant-store.ts` references it besides `graph-client.ts`):
- 20 "Sensitivity labels & label policies"
- 21 "Data loss prevention policies"
- 22 "Auto-labeling & sensitive information types"

Per-section decision table:

| Situation | Section status | Items | Adds to `syncErrors`? |
|---|---|---|---|
| Purview connection missing (`purviewRefreshToken` unset) | `not_connected` | keep existing | **No**, same rule as MDO and mailflow ("not-yet-configured is not a fault") |
| Entitlement is `not_entitled` | `unlicensed` (call skipped) | keep existing | **No** |
| Entitlement is `unknown` | attempt the call | per result | per result |
| Call succeeds | `ok`, `lastGoodAt` set | replaced | No |
| Call fails, classified `unlicensed` | `unlicensed` | keep existing | No |
| Call fails, anything else | `error` with message | **last-good preserved** | **Yes**, prefixed "Data Protection:" |

Why the no-error rows matter: `syncErrors.length > 0` sets `isPartial` and flips `connectionStatus` to `degraded`. A Business Premium tenant with no auto-labeling must stay `healthy`.

Other integration points:
- Runs after step 16 so licence evidence is already fetched this sync (use the fresh `licenseSkusLive` and `capabilitiesLive`, not the previous snapshot's).
- Snapshot assignment follows the `asrRulesLive !== null` convention: only overwrite a section when it produced a result.
- `tenant-store.ts`'s whole-sync retry on "Lifetime validation failed" applies to Graph tokens. The compliance token is a delegated token, so `withFreshTokenOnLifetimeError` does not apply, but the error classifier must still recognise the same message and mark it `transient`.
- Total time: three or more extra sequential REST calls. Budget with the existing timeouts and watch total sync duration in the live check.

## 1.7 Mock data
Four demo tenants, deliberately differentiated so every Stage 2 outcome (compliant, non-compliant, unknown, unlicensed) is reachable:

| Tenant | Licence archetype | Data protection state |
|---|---|---|
| Contoso Pharma | E5 | Full: labels with encryption on the top label, published policy with default and mandatory labeling, auto-label policy, health-focused DLP policies (one still in test mode, aged past 30 days) |
| Northwind Health | Business Premium | Manual labels, one Exchange/SharePoint/OneDrive DLP policy, **auto-labeling section `unlicensed`**, Teams and Endpoint not entitled |
| Fabrikam Logistics | E3 | Labels defined but **no label policy published**, no DLP policy |
| Woodgrove FSI | E5, strongest posture | PCI-style policy enabled, everything `ok` |

Also: at least one mock tenant (or a test fixture) with sections in `not_connected` and `error` (with last-good data), so those UI states can be seen. Mock SIT and label GUIDs come from the same constants Stage 3 will use (single source). Add each tenant's licence data in **live shape** (see 1.2).

## 1.8 Tests

| File | Covers |
|---|---|
| `data-protection-license.test.ts` | Entitlement table per archetype, tri-state, blank-snapshot returns `unknown`, mock-versus-live parity |
| `data-protection-mapper.test.ts` | Each mapper against real fixtures; SIT-condition parser cases; unknown enums; malformed rows; `backfillDataProtection`; `normalizeDataProtection(undefined)`; pre-feature snapshot round-trip |
| `purview-client.test.ts` | Mock only `global.fetch` (same approach as `graph-client.test.ts`): correct URL and scope, token cache keyed by resource, rotation callback fires, `classifyPurviewError` against captured text, no confident guess on unmatched text |
| `data-protection-sync.test.ts` | The decision table above, row by row; last-good preserved on error; `not_connected` and `unlicensed` never add a sync error; stale-refresh-token case (rotation between EXO and Purview steps uses the new token) |
| `capabilities-mapper` additions | Service plans captured; Business Premium legacy-name trap still holds |

The repository baseline before this work: 46 test files, 561 tests, all passing, `tsc --noEmit` clean. Stage 1 must leave both clean.

## 1.9 Delivery sequence
Small, independently reviewable commits, each leaving `tsc` and tests green:

1. **Types, blank, backfill, normalize** (no behaviour change; pre-feature snapshot test).
2. **Entitlements**: service-plan capture, `getDataProtectionEntitlements`, parity tests.
3. **Purview client and error classifier** (dead code until step 5; tests).
4. **Mappers** from Stage 0 fixtures (tests).
5. **Sync orchestrator and wiring**, including the `exoTenant` rotation fix, step count 19 to 22, decision table (tests).
6. **Mock data** for the four demo tenants plus the `isDemo` backfill entry.
7. **Purview connect step**: credential field, store handling, device-code start and poll routes, `PermissionsModal.tsx` step, and the connectivity self-test. (Moved ahead of step 5 in practice: sync cannot be tested live without a connection.)
8. **Vault**: see below.

## 1.10 Vault updates (same session as each change, per CLAUDE.md and AGENTS.md)
- [[Domain Types]]: new types, `dataProtection?` on the snapshot, `servicePlans?` on `TenantLicenseSku`.
- [[Core Graph Layer]]: steps 20 to 22, `TOTAL_SYNC_STEPS` 22, the `exoTenant` rotation wrapper, new `purview-client.ts` section.
- [[Tenant Store]]: `backfillSnapshot()` change and the `isDemo` list entry.
- [[Data Mappers]]: `data-protection-mapper.ts`.
- [[Testing]]: new test files and status of `purview-client.ts`.
- [[Security & Auth]]: the compliance resource, roles required, consent, and the new `purviewRefreshToken` credential.
- [[Modals]]: `PermissionsModal.tsx` Purview connect step.
- [[API Surface]]: `purview-connect/start` and `.../poll`.
- New note: `Data Protection (DLP & Sensitivity Labels)` under Services or Modules once Stage 2 exists; link from [[Clarity365 MOC]].
- [[Optimization Plan]]: record the two gaps below.

## Gaps found while planning (logged in [[Optimization Plan]])
1. **Stale in-memory EXO refresh token during a sync**: rotation persists to SQLite but not to the in-flight `tenant` object; masked today by the 55-minute access-token cache. Becomes live the moment a second Microsoft resource token is requested.
2. **`hasPurview` is E5-only and reports "Standard" (unlicensed) for E3 and Business Premium**, which include DLP core and manual labels. No consumer today, but any future gate on `cap-purview` would be wrong.

## Definition of done
- `tsc --noEmit` clean; full vitest suite green with the new files.
- A live E5 or Purview-capable tenant: sync populates all five sections, `status: ok`, GUID-keyed, visible in the stored snapshot.
- Same tenant with the delegated connection removed: sections become `not_connected`, last-good data preserved, tenant status stays `healthy`, no sync error added.
- A Business Premium tenant: auto-labeling and classifier sections `unlicensed`, tenant stays `healthy`.
- A snapshot saved before this feature loads in every existing module with no crash.
- Rotating the refresh token mid-sync (EXO step then Purview step) does not break the stored connection.
- Vault notes above updated.

## Risks and open questions
| Risk | Mitigation |
|---|---|
| Compliance REST endpoint or scope does not work with the existing delegated token | Stage 0 go or no-go; fallback is read-only via Graph where possible, or an app-only certificate path |
| Cmdlet output shapes differ from assumptions | Fixtures from Stage 0 only; unknown enums stay `unknown` |
| Refresh-token rotation semantics differ from the code comment | Design assumes the strict case (sequential, threaded token); Stage 0 measures the real behaviour |
| Sync duration grows | Sequential calls with per-call timeouts; measure in the live check; consider caching SITs |
| Snapshot size grows | Store only catalog-referenced and custom SITs; no raw cmdlet output |
| `types/index.ts` and `graph-client.ts` are hub files | Additive optional changes only; orchestration lives in a new file |
| Extra role or consent needed by the connecting admin | Stage 0 documents it; connectivity test reports `no_role` distinctly |

Resolved: optional field, separate Purview connect step, Crimson Line as the E5 test tenant (see Decisions above).

Still open:
1. Which admin account signs in for the Purview device-code step on Crimson Line, and does it hold a role that can read DLP and labels?
2. Does the tenant already contain any labels or DLP policies? If empty, seed a small known set (by hand in the Purview portal) so mapper fixtures cover populated data.
3. The unlicensed path needs a non-E5 tenant with a Purview connection. A Business Premium tenant from the fleet is the natural candidate; that tenant needs its own Purview sign-in, so choose one deliberately.
4. Is Endpoint DLP in scope for Stage 1 fixtures? It cannot be tested on Crimson Line.

Part of [[Clarity365 MOC]].
