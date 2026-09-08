---
tags: [module, compliance, reporting]
---

# Compliance Matrix (CIS M365 v3 / NIST CSF / Essential 8)

Scores a tenant against three external compliance frameworks simultaneously, derived from the same baseline data everything else uses.

- **Component:** `ComplianceMatrixModule.tsx`
- **Backing call:** `compliance-evaluator.evaluateTenantCompliance` / `evaluateFleetCompliance` (same data as `GET /api/reports/compliance`)
- **Key types:** `ComplianceControlItem`, `TenantComplianceAssessment` :  see [[Domain Types]]
- **Uses service:** [[Analysis & Generation]] (`compliance-evaluator`, which composes `ca-baseline-matcher` + `drift-analyzer`)

Part of [[Clarity365 MOC]]. Notable: this module doesn't introduce new source data :  it's a third *lens* (CIS/NIST/Essential 8) over the same [[Baseline Definitions & Mock Data|39 baseline rules]] every other module already scores against. Worth knowing if you're ever asked "is the compliance score consistent with the CA scanner" :  structurally, it has to be.
