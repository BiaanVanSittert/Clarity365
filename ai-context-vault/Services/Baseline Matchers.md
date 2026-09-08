---
tags: [service]
---

# Baseline Matchers

Five files, each scoring live tenant config against one category of [[Baseline Definitions & Mock Data|baseline rules]].

## ca-baseline-matcher.ts :  the most depended-on file in the codebase
No local imports (foundational leaf). Exports `matchCaBaselineCode`, `validateCaPolicyCompliance`, `computeBaselineCoveragePercent`. Reused directly by the four matchers below, plus [[Analysis & Generation]]'s `drift-analyzer`, `compliance-evaluator`, `fleet-analyzer`, `report-generator`, and by [[Tenant Store]] itself. Has a test.

## The other four
`groups-baseline-matcher.ts`, `mailflow-baseline-matcher.ts`, `mdo-baseline-matcher.ts`, `sharepoint-baseline-matcher.ts` :  each imports types + its own baseline-definitions file + `ca-baseline-matcher.computeBaselineCoveragePercent`, and exports one `evaluate*Baseline()` function. All four have tests.

| Matcher | Module that uses it |
|---|---|
| ca-baseline-matcher | [[Conditional Access Policy Scanner]], [[Fleet Baseline Rollout]] |
| groups-baseline-matcher | [[Groups & Distribution Management]] |
| mailflow-baseline-matcher | [[Mailflow Rules & Transport Hygiene]] |
| mdo-baseline-matcher | [[Defender for Office 365 & TABL]] |
| sharepoint-baseline-matcher | [[SharePoint & Storage Policies]] |

Part of [[Clarity365 MOC]].
