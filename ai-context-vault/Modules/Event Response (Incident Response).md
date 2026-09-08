---
tags: [module, security, fleet]
---

# Event Response (Incident Response)

Compromised-account containment and endpoint isolation/scan workflows, with MITRE-technique tagging per incident.

- **Component:** `EventResponseModule.tsx`
- **API routes:** `PATCH /api/tenants/{id}/incident-response/incidents/{incidentId}`, plus the modals below call their own routes
- **Key types:** `SecurityIncidentItem` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Drawer`, `EmptyStateRow`, `Pagination`, [[Modals#CompromisedAccountModal|CompromisedAccountModal]] (→ `POST .../contain-user`), [[Modals#DeviceIsolationModal|DeviceIsolationModal]] (→ `POST .../isolate-device`, `.../scan-device`)
- **Data origin:** [[Data Mappers]] (`incident-mapper`, incl. MITRE technique heuristics)

Part of [[Clarity365 MOC]]. Acts on devices classified by [[Intune Endpoint Security]] and accounts flagged by [[User & Account Classification]] / [[MFA Enforcement & Auth Audit]].
