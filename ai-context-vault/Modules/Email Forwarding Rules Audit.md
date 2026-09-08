---
tags: [module, exchange]
---

# Email Forwarding Rules Audit

Flags external-forwarding exfiltration vectors — transport rules, inbox rules, SMTP forwarding — with a live-write confirmation step before disabling anything.

- **Component:** `EmailForwardingModule.tsx`
- **API routes:** `POST /api/tenants/{id}/mailflow-fix` (disable_forwarding_rule)
- **Key types:** `EmailForwardingRule` — see [[Domain Types]]
- **Renders:** `StatusPill`, `Modal`
- **Write path:** [[Tenant Store]] → [[Core Graph Layer]] (`exo-client.disableForwardingRule`) — **untested**, see [[Testing]]

Part of [[Clarity365 MOC]]. One of the "High-Risk Threat Indicators" surfaced on the [[Overview Dashboard]]. See also [[Mailflow Rules & Transport Hygiene]] for the org-wide transport-rule baseline version of this same concern.
