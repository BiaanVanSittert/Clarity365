---
tags: [module, exchange]
---

# Domain Authentication (SPF / DKIM / DMARC)

Per-domain SPF/DKIM/DMARC posture. Unlike almost every other module, remediation here is raw DNS guidance text, not an automated write — there's no Graph/EXO API to "fix" someone else's DNS zone.

- **Component:** `DomainAuthModule.tsx`
- **Reads:** `TenantSecuritySnapshot` (prop-driven)
- **Key types:** `DomainAuthStatus` — see [[Domain Types]]
- **Renders:** `StatusPill`
- **Data origin:** [[Security Infra]] (`domain-dns-checker` — the only service file that queries public DNS instead of Graph/EXO)

Part of [[Clarity365 MOC]].
