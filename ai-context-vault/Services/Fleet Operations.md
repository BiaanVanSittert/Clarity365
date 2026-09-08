---
tags: [service, fleet]
---

# Fleet Operations

`src/lib/services/fleet-operations.ts` — the one file that **imports [[Tenant Store]]** rather than being imported by it. Architecturally, it sits *above* the store as a fleet-wide orchestration layer that fans a single operator action out across many tenants.

- Imports: `tenant-store`, types, `baseline-definitions`, `drift-analyzer`
- Exports: `getFleetTablEntries`/`addFleetTablEntry`/`removeFleetTablEntry` (cross-tenant TABL broadcast), `executeBulkCaDeployment`, `realignTenantDrift`
- **No test file**

## Used by
- [[Fleet Baseline Rollout]] → `executeBulkCaDeployment`
- [[Fleet Baseline Drift]] → `realignTenantDrift`
- [[Fleet TABL Sync]] → `getFleetTablEntries`/`add`/`remove`

Part of [[Clarity365 MOC]]. See [[Optimization Plan]] — this is the highest blast-radius code path in the app (one call can touch every tenant at once) and it's the one place in the [[Tenant Store]] dependency chain with zero test coverage.
