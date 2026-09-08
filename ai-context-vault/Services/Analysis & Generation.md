---
tags: [service]
---

# Analysis & Generation

Six files that compute derived findings on top of a snapshot, rather than mapping raw API data.

- **drift-analyzer.ts** :  `DEFAULT_GOLDEN_BASELINE`, `DRIFT_SEVERITY_WEIGHTS`, `evaluateTenantDrift`, `evaluateFleetDrift`, `realignFindingLocally`, `tenantHasEntraP2`. Imports [[Baseline Matchers]] (`ca-baseline-matcher`) and [[Data Mappers]] (`admin-hygiene-matcher`). Has a test. → [[Fleet Baseline Drift]]
  - `evaluateTenantDrift` computes two parallel per-tenant scores: `alignmentScore` (flat pass/total ratio, unchanged, still drives the existing `status`/KPI cards) and `weightedDriftScore` (severity-weighted: critical=30/high=15/medium=6/low=2 points per finding, capped at 100, higher = worse). `evaluateFleetDrift` sorts `tenantAssessments` descending by `weightedDriftScore` and adds `overallFleetWeightedDriftScore` (fleet mean) to `FleetDriftSummary`.
  - Golden Baseline checks include `SEC-ADMIN-LICENSE` (critical, `remediationSupported: false`) :  flags any admin account (`mfaAudit.isAdmin`) also carrying a daily-use Exchange/Teams license, via `admin-hygiene-matcher.findLicensedGlobalAdmins`. Same function also drives the "Licensed Admins" card in [[User & Account Classification]].
- **compliance-evaluator.ts** :  `evaluateTenantCompliance`/`evaluateFleetCompliance` across CIS M365 v3, NIST CSF 2.0, Essential Eight. Imports `ca-baseline-matcher` + `drift-analyzer`. Has a test. → [[Compliance Matrix (CIS-NIST-Essential 8)]]
- **fleet-analyzer.ts** :  second major hub: `calculateTenantMonthlyWaste`, `computeTenantCompositeRiskScore`, `aggregateFleetFailingBaselines`, `computeFleetPosture`, `computeFleetLicenseWaste`, `searchAcrossFleet`. Imports **all four non-CA baseline matchers**. Heavily used by [[Tenant Store]]. Has a test. → [[Fleet License Optimization]], [[Tenant License Optimization]], [[Executive Reporting (QBR)]]
- **report-generator.ts** :  `generateTenantQbrReport`. Imports `ca-baseline-matcher` + `fleet-analyzer`. Has a test. → [[Executive Reporting (QBR)]]
- **remediation-generator.ts** :  `generateRemediationPlanForTenant`, produces the PowerShell scripts shown in the UI (`RemediationDrawer`) and returned by the [[MCP Server]]'s `generate_remediation_plan` tool. Imports types only. **No test file** :  worth flagging since it's directly agent-facing output; see [[Testing]].
- **exchange-mailflow-score.ts** :  `computeExchangeMailflowScore`. Imports `mdo-baseline-matcher` + `mailflow-baseline-matcher`. Has a test. Used on the [[Overview Dashboard]].

Part of [[Clarity365 MOC]].
