---
tags: [module, fleet, conditional-access]
---

# Fleet Baseline Drift

Golden Baseline drift detection across the fleet, with 1-click realignment gauges per tenant, plus a **Tenant Drift Leaderboard** ranking every tenant by severity-weighted deviation from the Golden Standard.

- **Component:** `FleetBaselineDriftModule.tsx`
- **API routes:** `POST /api/fleet/drift`
- **Key types:** `FleetDriftSummary`, `TenantDriftAssessment`, `TenantDriftFinding`, `GoldenBaselineTemplate` :  see [[Domain Types]]
- **Renders:** [[Modals#ChangeConfirmationModal|ChangeConfirmationModal]] (mandatory review-before-push step)
- **Uses service:** [[Analysis & Generation]] (`drift-analyzer.evaluateFleetDrift`), write path via [[Fleet Operations]] (`realignTenantDrift`)

**Tenant Drift Leaderboard** (added to surface per-tenant drift, which previously existed in the data model but was never rendered): a dense table between the KPI cards and the findings table, ranking `tenantAssessments` by `weightedDriftScore` (0 to 100, higher = worse) instead of the older flat `alignmentScore` (0 to 100, higher = better). One critical finding (e.g. missing admin MFA) outweighs several medium/low ones by design :  see the scoring formula in [[Analysis & Generation]]. Columns: rank, tenant, drift % (with a small bar meter), status badge, critical/high/medium/low finding counts, drifted-rules ratio, and a "View Findings" action that filters the existing findings table to that tenant (reuses the existing `tenantFilter` state, no new filter mechanism). Has its own CSV export separate from the findings-level one.

Part of [[Clarity365 MOC]]. Defines the MSP's "Golden Baseline" that every tenant is measured against :  this is the closest thing the app has to a configurable policy-as-code source of truth.
