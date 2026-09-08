---
tags: [module, cost]
---

# Tenant License Optimization

Per-tenant license waste and cost breakdown (the single-tenant lens on the same problem [[Fleet License Optimization]] solves fleet-wide).

- **Component:** `TenantLicenseOptimizationModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Backing call:** `fleet-analyzer.calculateTenantMonthlyWaste`
- **Uses service:** [[Analysis & Generation]] (`fleet-analyzer`)

Part of [[Clarity365 MOC]]. Depends on [[User & Account Classification]] for the underlying orphan/disabled-seat counts it prices out.
