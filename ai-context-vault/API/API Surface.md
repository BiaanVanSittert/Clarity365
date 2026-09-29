---
tags: [api]
---

# API Surface

44 routes under `src/app/api/` (33, plus the 8 added for [[Audit Log Investigator]], plus 3 for [[Defender Configuration & Onboarding]]/[[Attack Surface Reduction Rules]]'s Phase 2 write path). Nearly all funnel through [[Tenant Store]]; the `fleet/*` bulk-action routes go through [[Fleet Operations]] instead.

## Tenants (core)
| Route | Methods | Calls |
|---|---|---|
| `/api/tenants` | GET/POST/DELETE | Tenant Store |
| `/api/tenants/[id]` | GET/PUT | Tenant Store |
| `/api/tenants/[id]/sync` | POST | Tenant Store (`syncTenant`, live Graph pull w/ cache fallback) |
| `/api/tenants/[id]/sync-progress` | GET | Tenant Store (`getSyncProgress`) - polled during a sync for the live step/percent progress bar |
| `/api/tenants/[id]/permissions` | GET | Tenant Store (`testPermissions`) |
| `/api/tenants/[id]/exo-permissions` | GET | Tenant Store (`testExoConnectivity`) |
| `/api/tenants/[id]/exo-connect/start`, `/poll` | POST | Tenant Store (device-code EXO auth) |

## Audit Log Investigator
| Route | Methods | Calls |
|---|---|---|
| `/api/tenants/[id]/audit-log/upload` | POST | Tenant Store (`ingestAuditLogCsv`, streaming CSV parse) |
| `/api/tenants/[id]/audit-log/import-progress` | GET | Tenant Store (`getAuditImportProgress`) - polled during an upload |
| `/api/tenants/[id]/audit-log/imports` | GET/DELETE | Tenant Store (`getAuditLogImports`/`deleteAuditLogImport`) |
| `/api/tenants/[id]/audit-log/search` | GET | Tenant Store (`searchAuditLogRecords`) |
| `/api/tenants/[id]/audit-log/session/[sessionId]` | GET | Tenant Store (`getAuditLogSessionTimeline`) |
| `/api/tenants/[id]/audit-log/typeahead` | GET | Tenant Store (`getAuditLogTypeahead`) |
| `/api/tenants/[id]/audit-log/template-counts` | GET | Tenant Store (`getAuditLogTemplateCounts`) - Phase 2 |
| `/api/tenants/[id]/audit-log/flags` | GET | Tenant Store (`getAuditLogFlags`) - Phase 3 |

All eight → [[Audit Log Investigator]].

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

## Endpoint Security (Phase 2 write path)
| Route | Methods | Calls |
|---|---|---|
| `/api/tenants/[id]/endpoint-security/defender-av-policy` | GET/POST | `getDefenderAvPolicy`/`deployDefenderAvPolicy` → [[Defender Configuration & Onboarding]] |
| `/api/tenants/[id]/endpoint-security/edr-policy` | GET/POST | `getEdrPolicy`/`deployEdrPolicy` → [[Defender Configuration & Onboarding]] |
| `/api/tenants/[id]/endpoint-security/bitlocker-policy` | GET/POST | `getBitLockerPolicy`/`deployBitLockerPolicy` → [[Defender Configuration & Onboarding]] |
| `/api/tenants/[id]/endpoint-security/asr-deploy` | POST | `deployAsrRules` → [[Attack Surface Reduction Rules]] |
| `/api/tenants/[id]/endpoint-security/mde-connector` | PATCH | `updateMdeConnectorSettings` → [[Defender Configuration & Onboarding]] |

All five check `tenant.endpointSecurityWriteMode === "write_enabled"` before calling Tenant Store (the second gate, the actual Graph permission, isn't re-checked server-side - a missing grant surfaces as a Graph 403, same convention as `deploy-ca`).

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
