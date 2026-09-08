---
tags: [module]
---

# App Registrations & Connected Services

Enterprise apps / App Registrations audit — high-privilege Graph scopes and expiring credentials.

- **Component:** `AppRegistrationsModule.tsx`
- **Reads:** `TenantSecuritySnapshot.appRegistrations` (prop-driven)
- **Key types:** `AppRegistrationItem` — see [[Domain Types]]
- **Renders:** `StatusPill`
- **Data origin:** [[Data Mappers]] (`app-registration-mapper`) — also risk-categorizes each app

Part of [[Clarity365 MOC]]. This module's own app registration (the one Clarity365 itself runs as) is what [[Security & Auth]] and the Permissions modal validate on setup.
