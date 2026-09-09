---
tags: [module, fleet, cost]
---

# Fleet License Optimization

Fleet-wide license waste analysis :  dormant, shared-mailbox, disabled-user, and unassigned-seat costs across every tenant.

- **Component:** `FleetLicenseOptimizationModule.tsx`
- **Backing call:** `fleet-analyzer.computeFleetLicenseWaste` (no direct fetch; loops `calculateTenantMonthlyWaste` per snapshot)
- **Key types:** `FleetLicenseOptimizationItem`, `TenantLicenseSku` :  see [[Domain Types]]
- **Renders:** `Skeleton`
- **Uses service:** [[Analysis & Generation]] (`fleet-analyzer`)

`wasteByCategory.unassignedSkus` rolls up `unassigned_license_sku` items :  purchased-but-idle seats from each tenant's `licenseSkus` (populated from Graph's `/subscribedSkus`, `consumedUnits` vs `prepaidUnits.enabled`), same tier-cost pricing model as every other waste category.

Part of [[Clarity365 MOC]]. Fleet-wide sibling of [[Tenant License Optimization]]; both read the same waste-scoring logic in `fleet-analyzer`.
