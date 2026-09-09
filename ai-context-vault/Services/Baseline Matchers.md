---
tags: [service]
---

# Baseline Matchers

Five files, each scoring live tenant config against one category of [[Baseline Definitions & Mock Data|baseline rules]].

## ca-baseline-matcher.ts :  the most depended-on file in the codebase
No local imports (foundational leaf). Exports `matchCaBaselineCode`, `classifyPolicyBaselineCode`, `policyNameMatchesCode`, `validateCaPolicyCompliance`, `computeBaselineCoveragePercent`. Reused directly by the four matchers below, plus [[Analysis & Generation]]'s `drift-analyzer`, `compliance-evaluator`, `fleet-analyzer`, `report-generator`, and by [[Tenant Store]] itself. Has a test.

`matchCaBaselineCode` is deliberately structural-only (conditions/grantControls, never the policy's name) - a misleading name shouldn't make a badly-configured policy look compliant. But that also meant any unrelated tenant policy that happened to overlap a baseline's settings got reported as that baseline's deployed policy (a real tenant had a policy literally named "mod" reported as its CA06, and "Test Md102" as its CA09). Fixed with two additions, not a change to `matchCaBaselineCode` itself (its narrow contract and existing tests stay valid):
- `policyNameMatchesCode(name, code)` checks the "CA0X: <description>" convention (the same one `deployBaselinePolicy` in [[Tenant Store]] already used to find its own deployed policies).
- `classifyPolicyBaselineCode(policy)` requires BOTH a structural match (via `matchCaBaselineCode`) AND a naming match before attributing a policy to a code - this is what `graph-client.ts`'s live sync classification and [[Conditional Access Policy Scanner]]'s unlabeled-policy fallback now call, instead of the raw structural matcher.
- `validateCaPolicyCompliance` (the actual compliance gate, used by every consumer in the table below) now also requires the naming match, so even a policy someone else's loose `.find()` heuristic mismatches onto the wrong code will correctly fail validation rather than being silently credited.

Also fixed in the same pass: `matchCaBaselineCode`'s CA09 branch only recognized `compliantDevice`/`domainJoinedDevice`, while `validateCaPolicyCompliance`'s own CA09 check already accepted the BYOD-equivalent `appProtectionPolicy`/`approvedApplication` controls too - the two disagreed on what counts as CA09, so an app-protection-based CA09 policy could pass one check and fail the other. Both now accept the same four controls. (Surfaced by fixing a mislabeled Contoso demo policy - see [[Baseline Definitions & Mock Data]].)

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
