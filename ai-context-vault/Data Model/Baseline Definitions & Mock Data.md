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

## Snapshot scaffolding
- **default-snapshot.ts** :  `createBlankSnapshot()`, the single source of truth for an empty [[Domain Types#The hub type|`TenantSecuritySnapshot`]], seeded with 4 base capabilities. Used for brand-new tenants and as the pre-sync scaffold.
- **mock-tenants.ts** (2330 lines) :  `INITIAL_TENANTS` (4 demo orgs: Contoso Pharma, Northwind Health, Fabrikam Logistics, Woodgrove FSI) + `MOCK_TENANT_DATA`, one full realistic snapshot per tenant. This is the entire demo/simulation-mode dataset :  see also `scripts/installer.js`, which seeds these same four tenants (named slightly differently there: Contoso E5, Northwind BP, Fabrikam E3, Woodgrove Zero-Trust) on first launch.

Also fixed: Contoso's `ca-pol-04` was mislabeled - named/scoped as CA01 to CA10's slot 4 but actually a device-compliance policy (CA09's real shape: `compliantDevice`/`domainJoinedDevice` controls), not CA04's real definition (guest-access MFA, per [[Baseline Matchers]]). It only worked "by accident" because a CIS control's loose name-substring `.find()` picked it up as evidence for CA09 being satisfied. Now genuinely represents CA04 (MFA scoped to `GuestsOrExternalUsers`) - see [[Baseline Matchers]] for the related `ca-baseline-matcher.ts` naming-convention fix this uncovered.

Part of [[Clarity365 MOC]].
