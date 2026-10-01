---
tags: [data-model]
---

# Baseline Definitions & Mock Data

`src/lib/data/*.ts` :  the app's scoring taxonomy and demo dataset.

## 39 baseline rules across 5 categories
| File                                                                   | Rules          | Auto-fixable                                                                                            |
| ---------------------------------------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------- |
| `baseline-definitions.ts` :  `CA_BASELINE_STANDARDS`                    | 10 (CA01 to CA10) | All :  each ships a full PowerShell/Graph SDK deployment template with break-glass exclusion boilerplate |
| `mdo-baseline-definitions.ts` :  `MDO_BASELINE_STANDARDS`               | 9 (MDO01 to 09)   | 8 of 9 :  MDO09 is a judgment call, no auto-fix                                                          |
| `mailflow-baseline-definitions.ts` :  `MAILFLOW_BASELINE_STANDARDS`     | 8 (MF01 to 08)    | 5 of 8 :  MF03/MF05/MF06 are manual-review-only                                                          |
| `groups-baseline-definitions.ts` :  `GROUPS_BASELINE_STANDARDS`         | 7 (G01 to G07)    | None yet :  all judgment calls or unconfirmed write paths                                                |
| `sharepoint-baseline-definitions.ts` :  `SHAREPOINT_BASELINE_STANDARDS` | 5 (SP01 to 05)    | None yet :  same reasoning                                                                               |

This is the natural top-level taxonomy for the whole app: every [[Clarity365 MOC#Modules|module]] that isn't UI chrome is ultimately scoring, deploying, or reporting on some subset of these 39 rules.

## Woodgrove demo CA fix (2026-09-29)
Woodgrove, the "100% coverage" zero-trust demo tenant, generated all ten CA01-CA10 policies from one template ("MFA for all users"), so **8 of 10 failed `validateCaPolicyCompliance`**: no legacy block, no country block, no compliant device, no risk conditions. Each now has its real shape (`WOODGROVE_BASELINE_OVERRIDES` in `mock-tenants.ts`), plus four non-baseline policies (device-code/auth-transfer block, security-info registration, token protection, insider risk in report-only). Admin policies use live-shape role template GUIDs via `includeRoles`, so both CA identifier dialects appear in demo data (see [[Security Simulations Plan]]). `mock-tenants.test.ts` guards this. All four demo tenants also gained `namedLocations` and `identitySettings` with different profiles: Woodgrove strict, Contoso mixed, Northwind and Fabrikam permissive.

## Snapshot scaffolding
- **default-snapshot.ts** :  `createBlankSnapshot()`, the single source of truth for an empty [[Domain Types#The hub type|`TenantSecuritySnapshot`]], seeded with 4 base capabilities. Used for brand-new tenants and as the pre-sync scaffold.
- **mock-tenants.ts** (2330 lines) :  `INITIAL_TENANTS` (4 demo orgs: Contoso Pharma, Northwind Health, Fabrikam Logistics, Woodgrove FSI) + `MOCK_TENANT_DATA`, one full realistic snapshot per tenant. This is the entire demo/simulation-mode dataset :  see also `scripts/installer.js`, which seeds these same four tenants (named slightly differently there: Contoso E5, Northwind BP, Fabrikam E3, Woodgrove Zero-Trust) on first launch.

Also fixed: Contoso's `ca-pol-04` was mislabeled - named/scoped as CA01 to CA10's slot 4 but actually a device-compliance policy (CA09's real shape: `compliantDevice`/`domainJoinedDevice` controls), not CA04's real definition (guest-access MFA, per [[Baseline Matchers]]). It only worked "by accident" because a CIS control's loose name-substring `.find()` picked it up as evidence for CA09 being satisfied. Now genuinely represents CA04 (MFA scoped to `GuestsOrExternalUsers`) - see [[Baseline Matchers]] for the related `ca-baseline-matcher.ts` naming-convention fix this uncovered.

**`graph-permissions.ts` (2026-10-01):** the single list of Microsoft Graph application permissions (`GRAPH_PERMISSIONS`: 16 required read-only rows covering 17 permission names, 4 optional), with the name(s) to grant, the sync steps each unlocks and the self-test endpoint. Client-safe. Add a permission here and it appears in onboarding, the Permissions check and the sync's error handling at once. Guard tests in `sync-permission-errors.test.ts`.

Part of [[Clarity365 MOC]].
