---
tags: [optimization, plan, data-protection]
---

# Sensitivity Labels Catalog — Plan

Status: **planning only, no code written** (drafted 2026-09-22). Direct gap found by the user: `DataProtectionModule.tsx` is titled "Data Protection (DLP & Sensitivity Labels)" and all 9 shipped entries are DLP rules - nothing recommends an actual label taxonomy, label policy, or auto-labeling. Part of [[DLP & Sensitivity Labels Plan]] and [[Optimization Plan]].

## Why this needs its own plan, not just more catalog entries
`DlpRecommendation` (the existing type) is shaped around a DLP rule: Sensitive Information Types, locations, a single rule-logic statement, a start mode. A label recommendation is structurally different - it's a **taxonomy** (a small set of named labels with priority/encryption/markings) plus a **label policy** (which labels are published where, a default, mandatory labeling, downgrade justification) plus, optionally, an **auto-labeling policy** (E5). Forcing that into the existing fields would misrepresent it the same way merging the two POPIA entries would have - see the precedent already set on that call.

## Research grounding
Verified against Microsoft Learn during planning (not asserted from memory, same discipline as the DLP catalog):
- **`New-Label`** creates a label: key parameters `Name`/`DisplayName`, `ToolTip` (what the user sees), `AdvancedSettings` (hashtable for less-common settings). ([Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-label?view=exchange-ps))
- **`New-LabelPolicy`** publishes labels to locations: `Name`, `Labels` (array), `ExchangeLocation`/`OneDriveLocation`/`SharePointLocation`/`SkypeLocation` (Teams)/`ModernGroupLocation` (container labels), each with an `Except*` exclusion counterpart. ([Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-labelpolicy?view=exchange-ps))
- **`New-AutoSensitivityLabelPolicy`** + **`New-AutoSensitivityLabelRule`**: `Name`, `ApplySensitivityLabel`, `Mode` (`Enable`/`TestWithNotifications`/`TestWithoutNotifications` - the same three-state convention the DLP catalog already uses), plus locations. ([Microsoft Learn](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-autosensitivitylabelpolicy?view=exchange-ps))

This is materially better-documented than the `ip_contracts` trainable-classifier gap - these cmdlets and their parameters are confirmed, not a guess. PowerShell templates for labels can carry normal confidence, not the "policy shell only" caveat `ip_contracts` needed.

## Proposed taxonomy (draft, needs sign-off before content is built)
Four tiers, matching the shape already floated in this project's first planning pass:

| Label | Priority | Encryption | Typical trigger |
|---|---|---|---|
| Public | 0 (lowest) | No | Marketing material, public-facing content |
| General | 1 | No | Default label - everyday internal business content |
| Confidential | 2 | No | Client data, contracts, financial reports |
| Highly Confidential | 3 (highest) | Yes | PHI, government IDs, credentials, anything a DLP entry already treats as high-severity |

Sublabels only where a specific regulation's DLP entry already implies one (e.g. "Highly Confidential - PHI" under HIPAA, "Highly Confidential - POPIA" per the existing POPIA/cross-border entries) - cross-referenced via the same `relatedRecommendationIds` mechanism already built for DLP, so a label recommendation and its matching DLP entry link to each other.

## Proposed catalog shape
New type, `LabelRecommendation`, added to the same `data-protection-recommendations.ts` file (not a separate file - keeps the "one catalog" mental model the compliance-matrix integration reinforced) or the module gains a `kind: "dlp" | "label"` discriminant on a shared list. Fields (draft):

```ts
interface LabelRecommendation {
  id: string;
  kind: "label";
  title: string;
  regulations: Regulation[];       // [] for the baseline taxonomy - it's general hygiene, not regulation-specific
  minimumLicenseTier: LicenseTier;
  summary: string;
  labels: { name: string; priority: number; encrypted: boolean; contentMarking: boolean; tooltip: string }[];
  labelPolicySettings: { defaultLabelName?: string; mandatoryLabeling: boolean; requireDowngradeJustification: boolean; locations: string[] };
  autoLabeling?: { targetLabelName: string; sitReferences: string[]; mode: "Test with notifications" | "Test without notifications" }; // E5 only, omitted for the base entry
  portalSteps: GuidedPortalStep[];
  powershellTemplate: (policyNamePrefix: string) => string;
  e5Enhancements?: string[];
  regulationRefs: RegulationReference[];
  caveats: string[];
  relatedRecommendationIds?: string[];  // links to matching DLP entries
}
```

## Proposed first entries (draft, for review)
1. **Baseline four-tier label taxonomy + mandatory labeling** - no regulation tag (general hygiene, same treatment `credentials-and-secrets-leak-prevention` got). Business Premium/E3. Publishes all four labels, sets General as default, mandatory labeling on, no encryption yet (that's the next entry) - deliberately the smallest possible first step, matching the DLP catalog's own "start in test mode" caution.
2. **Highly Confidential encryption** - extends entry 1: adds encryption + content marking to the top label. Business Premium/E3 (manual labels + encryption are available there; only *auto*-labeling needs E5).
3. **Auto-labeling for PHI / SA ID / government ID content** - E5 only, reuses the SITs already defined in `hipaa-phi`, `popia-sa-id-and-health`, `gdpr-uk-government-id-and-special-category` via `New-AutoSensitivityLabelRule`. Cross-linked to those three DLP entries both directions.
4. **Container labels for Teams and SharePoint sites** - needs Entra ID P1 for the label to actually gate group/site settings (per Microsoft's own documented prerequisite) - this needs a quick verify-before-claiming pass, flagged as a caveat until confirmed live or against docs directly, same standard as everything else in this catalog.

## UI integration
- `DataProtectionModule.tsx`'s single list gains label entries alongside DLP ones, visually distinguished (a small "Label" vs "DLP" tag on each card) - not a separate module, matching the "let it live together" preference already established for Compliance Matrix.
- `FleetDataProtectionModule.tsx`'s matrix naturally extends to label entries too, since it already keys off `minimumLicenseTier` generically - no redesign needed there, just more columns.
- `relatedRecommendationIds` cross-links a label entry to its matching DLP entry and back, reusing the exact mechanism already built and tested for the two POPIA entries.

## Decisions (2026-09-22) and shipped status
1. **Placement: a category under the existing DLP module** - user's explicit direction ("make it a category under the DLP"). Implemented as a `kind: "label"` discriminant in the same `DATA_PROTECTION_RECOMMENDATIONS` array and the same `DataProtectionModule.tsx`, not a separate module.
2. **Taxonomy and entries: built as drafted** ("proceed with the sensitivity label implementation") - four-tier taxonomy, all four proposed entries shipped as-is.
3. **Auto-labeling tier: E5-only, no Business Premium/E3 fallback** - the `ip_contracts` precedent re-applied, for the same reason (a weak imitation of automation would be worse than no entry).
4. **Container labels' Entra ID P1 prerequisite: shipped with a caveat, not verified live** - flagged explicitly in the entry's own caveats rather than blocking the whole entry on a live-verification pass that wasn't available.

**Shipped**: `LabelRecommendation` type; four entries (`label-baseline-taxonomy`, `label-highly-confidential-encryption`, `label-auto-labeling-sensitive-categories`, `label-container-labels`); cross-links to `hipaa-phi`, `popia-sa-id-and-health`, `gdpr-uk-government-id-and-special-category`; `DataProtectionModule.tsx` updated with a real type predicate for the union, a DLP/Label badge, and a kind filter; `compliance-evaluator.ts`'s DLP-eligibility control deliberately still DLP-only; `query_data_protection_recommendations` MCP tool updated. `tsc` clean; 568 tests passing (no new automated tests added for the label entries themselves - see Known gap below). Full detail: [[Data Protection (DLP & Sensitivity Labels)]].

## Known gap
Unlike the DLP catalog (which has no dedicated content tests either, to be fair, but does have `data-protection-tier-gating.test.ts` covering the shared logic it depends on), the four label entries shipped with no new test coverage of their own - there's no pure logic here beyond what `getTierEligibility()` already tests (reused unchanged). Worth a light smoke test later (e.g. "every label entry has at least one label, every DLP entry has no `labels` field") if the catalog keeps growing, but not done in this pass.

Part of [[DLP & Sensitivity Labels Plan]] and [[Clarity365 MOC]].
