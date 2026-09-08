---
tags: [module, conditional-access]
---

# Conditional Access Policy Scanner

CA01 to CA10 baseline policy scanner with report-only detection. The original flagship module.

- **Component:** `ConditionalAccessModule.tsx`
- **Reads:** `TenantSecuritySnapshot.conditionalAccess` (prop-driven, no direct fetch)
- **Key types:** `CAPolicyRule`, `CABaselineItem` :  see [[Domain Types]]
- **Uses service:** [[Baseline Matchers]] (`ca-baseline-matcher` :  the most depended-on file in the codebase)
- **Renders:** `StatusPill`, [[Modals#DeployCaPolicyModal|DeployCaPolicyModal]] (→ `POST /api/tenants/{id}/deploy-ca`)
- **Baseline source:** [[Baseline Definitions & Mock Data]] :  `CA_BASELINE_STANDARDS` (10 rules, each with a full deployment template)

Part of [[Clarity365 MOC]]. See also [[Fleet Baseline Rollout]] and [[Fleet Baseline Drift]] for the cross-tenant versions of this same CA01 to CA10 logic.

**Known-fixed bug class:** `matchCaBaselineCode`/`validateCaPolicyCompliance` are called twice per policy :  once at sync time in [[Core Graph Layer]] against the raw Graph response, once here (and in drift-analyzer) against the *stored* `CAPolicyRule`. Any `conditions`/`grantControls` field the graph-client mapping doesn't carry through will make a genuinely-correct live policy misclassify as "Missing"/"Misconfigured" on the second pass even though the first pass got it right. `locations`, `platforms`, `userRiskLevels`, `signInRiskLevels`, `includeRoles`, and `grantControls.authenticationStrength` were all silently dropped this way (affecting CA03/CA06/CA07/CA08/CA10 on live tenants) until fixed in [[Core Graph Layer]] :  if a new baseline code's re-validation looks wrong on a live tenant but not on mock data, check this mapping first.
