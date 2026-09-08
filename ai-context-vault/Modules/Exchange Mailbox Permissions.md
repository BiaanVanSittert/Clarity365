---
tags: [module, exchange]
---

# Exchange Mailbox Permissions

Audits FullAccess/SendAs/SendOnBehalf mailbox delegation, flags licensed shared-mailbox cost waste, one-click delegation revoke.

- **Component:** `MailboxPermissionsModule.tsx`
- **API routes:** `POST /api/tenants/{id}/mailflow-fix` (revoke_delegation, enable_mailbox_auditing)
- **Key types:** `MailboxItem`, `MailboxDelegation` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Modal`, `EmptyStateRow`
- **Write path:** [[Tenant Store]] → [[Core Graph Layer]] (`exo-client.removeMailboxDelegation`) :  **untested** (`exo-client.ts` has no `.test.ts`, see [[Testing]])

Part of [[Clarity365 MOC]]. Shares its fix API and write path with [[Email Forwarding Rules Audit]].
