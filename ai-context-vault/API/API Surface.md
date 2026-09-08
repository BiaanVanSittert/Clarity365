---
tags: [api]
---

# API Surface

33 routes under `src/app/api/`. Nearly all funnel through [[Tenant Store]]; the `fleet/*` bulk-action routes go through [[Fleet Operations]] instead.

## Tenants (core)
| Route | Methods | Calls |
|---|---|---|
| `/api/tenants` | GET/POST/DELETE | Tenant Store |
| `/api/tenants/[id]` | GET/PUT | Tenant Store |
| `/api/tenants/[id]/sync` | POST | Tenant Store (`syncTenant`, live Graph pull w/ cache fallback) |
| `/api/tenants/[id]/permissions` | GET | Tenant Store (`testPermissions`) |
| `/api/tenants/[id]/exo-permissions` | GET | Tenant Store (`testExoConnectivity`) |
| `/api/tenants/[id]/exo-connect/start`, `/poll` | POST | Tenant Store (device-code EXO auth) |

## Tenant actions (writes)
| Route | Calls |
|---|---|
| `/api/tenants/[id]/deploy-ca` | `deployBaselinePolicy` → [[Conditional Access Policy Scanner]] |
| `/api/tenants/[id]/groups` | `addGroup` → [[Groups & Distribution Management]] |
| `/api/tenants/[id]/sharepoint` | `updateSharePointPolicy` → [[SharePoint & Storage Policies]] |
| `/api/tenants/[id]/tabl` | `addTablEntry`/`removeTablEntry` → [[Defender for Office 365 & TABL]] |
| `/api/tenants/[id]/mailflow-fix` | disable_forwarding_rule / revoke_delegation / enable_mailbox_auditing → [[Email Forwarding Rules Audit]], [[Exchange Mailbox Permissions]] |
| `/api/tenants/[id]/mailflow-baseline-fix` | `applyMailflowBaselineFix` → [[Mailflow Rules & Transport Hygiene]] |
| `/api/tenants/[id]/mdo-fix` | `applyMdoBaselineFix` → [[Defender for Office 365 & TABL]] |

## Incident response
| Route | Calls |
|---|---|
| `/api/tenants/[id]/incident-response/contain-user` | `containUserAccount`/`restoreUserAccount` |
| `/api/tenants/[id]/incident-response/isolate-device` | `isolateEndpointDevice`/`releaseEndpointDevice` |
| `/api/tenants/[id]/incident-response/scan-device` | `scanEndpointDevice` |
| `/api/tenants/[id]/incident-response/incidents/[incidentId]` | PATCH `updateSecurityIncident` |

All four → [[Event Response (Incident Response)]].

## Fleet (goes through [[Fleet Operations]], not Tenant Store directly, for the bulk-write ones)
| Route | Methods | Calls |
|---|---|---|
| `/api/fleet/posture` | GET | Tenant Store (`getFleetPosture`) |
| `/api/fleet/license-waste` | GET | Tenant Store (`getFleetLicenseWaste`) |
| `/api/fleet/search` | GET | Tenant Store (`searchFleet`) |
| `/api/fleet/drift` | GET/POST | `drift-analyzer.evaluateFleetDrift`, Fleet Operations (`realignTenantDrift`) |
| `/api/fleet/bulk-deploy` | POST | Fleet Operations (`executeBulkCaDeployment`) |
| `/api/fleet/sync-tabl` | GET/POST/DELETE | Fleet Operations |

## Reports & system
| Route | Calls |
|---|---|
| `/api/reports/compliance` | `compliance-evaluator` → [[Compliance Matrix (CIS-NIST-Essential 8)]] |
| `/api/reports/qbr` | `report-generator` → [[Executive Reporting (QBR)]] |
| `/api/audit-log` | Tenant Store (`getAuditLog`) → [[Audit Log Viewer]] |
| `/api/settings` | Tenant Store (`getSettings`/`updateSettings`) |
| `/api/mcp` | `mcp/engine.executeMcpTool`, gated by `settings.enableMcpServer` → [[MCP Server]] |

## Auth (see [[Security & Auth]] for the full flow)
| Route | Calls |
|---|---|
| `/api/auth/status` | `isPasswordConfigured` (public) |
| `/api/auth/setup` | `crypto.hashPassword` + `auth.createSessionToken` (first-run only) |
| `/api/auth/login` | `crypto.verifyPasswordHash` + `auth.createSessionToken` + rate-limit |
| `/api/auth/logout` | clears session cookie |
| `/api/auth/change-password` | `crypto.verifyPasswordHash`/`hashPassword` + rate-limit |

Part of [[Clarity365 MOC]].
