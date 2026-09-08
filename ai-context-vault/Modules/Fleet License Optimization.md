---
tags: [module, fleet, cost]
---

# Fleet License Optimization

Fleet-wide license waste analysis — dormant, shared-mailbox, and disabled-user seats costing money across every tenant.

- **Component:** `FleetLicenseOptimizationModule.tsx`
- **Backing call:** `fleet-analyzer.computeFleetLicenseWaste` (no direct fetch)
- **Key types:** `FleetLicenseOptimizationItem` — see [[Domain Types]]
- **Renders:** `Skeleton`
- **Uses service:** [[Analysis & Generation]] (`fleet-analyzer`)

Part of [[Clarity365 MOC]]. Fleet-wide sibling of [[Tenant License Optimization]]; both read the same waste-scoring logic in `fleet-analyzer`.
