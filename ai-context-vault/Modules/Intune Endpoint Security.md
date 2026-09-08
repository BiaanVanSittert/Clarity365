---
tags: [module]
---

# Intune Endpoint Security

Fleet antivirus/EDR onboarding status per device, Windows/macOS/Linux.

- **Component:** `IntuneSecurityModule.tsx`
- **Reads:** `TenantSecuritySnapshot.intune` (prop-driven)
- **Key types:** `IntuneDevice`, `IntunePolicySummary` — see [[Domain Types]]
- **Renders:** `StatusPill`, `Drawer`, `EmptyStateRow`
- **Data origin:** [[Data Mappers]] (`intune-mapper`)

Part of [[Clarity365 MOC]]. Devices flagged here are what [[Event Response (Incident Response)]] isolates/scans during an incident.
