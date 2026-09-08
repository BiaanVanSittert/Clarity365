---
tags: [module, fleet, conditional-access]
---

# Fleet Baseline Rollout

Cross-tenant bulk CA01–CA10 deployment matrix — the fleet-wide version of [[Conditional Access Policy Scanner]].

- **Component:** `FleetBaselineRolloutModule.tsx`
- **Opens:** [[Modals#FleetBulkDeployModal|FleetBulkDeployModal]] → `POST /api/fleet/bulk-deploy`
- **Uses services:** `drift-analyzer.tenantHasEntraP2` (license-gates CA07 risk-based controls), `ca-baseline-matcher.validateCaPolicyCompliance` — see [[Analysis & Generation]], [[Baseline Matchers]]
- **Write path:** [[Fleet Operations]] (`executeBulkCaDeployment`) — sits *above* [[Tenant Store]] rather than inside it

Part of [[Clarity365 MOC]]. Ships CA policies live across every tenant at once — see [[Optimization Plan]] for the blast-radius concern this raises.
