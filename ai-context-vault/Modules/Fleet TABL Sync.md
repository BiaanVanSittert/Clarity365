---
tags: [module, fleet]
---

# Fleet TABL Sync

Broadcasts a threat indicator (blocked sender/domain/URL/file) from one tenant's Tenant Allow/Block List to every tenant in the fleet, or removes one everywhere.

- **Component:** `FleetTablSyncModule.tsx`
- **API routes:** `GET`/`POST`/`DELETE /api/fleet/sync-tabl`
- **Key types:** `FleetTablEntry` — see [[Domain Types]]
- **Renders:** [[Modals#ChangeConfirmationModal|ChangeConfirmationModal]]
- **Write path:** [[Fleet Operations]] (`getFleetTablEntries`/`addFleetTablEntry`/`removeFleetTablEntry`)

Part of [[Clarity365 MOC]]. Cross-tenant sibling of the single-tenant TABL manager in [[Defender for Office 365 & TABL]] — and of the MCP `manage_tabl` tool in [[MCP Server]].
