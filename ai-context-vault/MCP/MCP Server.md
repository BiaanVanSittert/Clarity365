---
tags: [mcp]
---

# MCP Server

In-house Model Context Protocol server exposing 10 tools for AI agents / local SOC automation. `src/lib/mcp/definitions.ts` (schemas) + `src/lib/mcp/engine.ts` (`executeMcpTool`, wraps every call in [[Audit Log Viewer|audit logging]] regardless of outcome), served via `POST /api/mcp` (`GET /api/mcp` returns the tool list + status), gated by `settings.enableMcpServer` and sitting behind the same session middleware as everything else.

| Tool                        | Calls                                                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list_tenants`              | [[Tenant Store]] `getAllTenants()` + `getSnapshot()` per tenant                                                                                   |
| `get_tenant_secure_score`   | `getSnapshot()` → reads `secureScore`                                                                                                             |
| `audit_conditional_access`  | `getSnapshot()` → reads pre-computed `conditionalAccess` (no live matcher call)                                                                   |
| `query_signin_logs`         | `getSnapshot()` → filters `signIns`                                                                                                               |
| `audit_mfa_methods`         | `getSnapshot()` → filters `mfaAudit`                                                                                                              |
| `audit_email_forwarding`    | `getSnapshot()` → reads `emailForwarding`                                                                                                         |
| `manage_tabl`               | `getSnapshot()` (list) / `addTablEntry()` / `removeTablEntry()` :  **the only tool with a write path**, gated behind `Settings.allowToolExecution` |
| `generate_remediation_plan` | `getSnapshot()` + [[Analysis & Generation]]'s `remediation-generator.generateRemediationPlanForTenant()`                                          |
| `query_data_protection_recommendations` | Reads the static `DATA_PROTECTION_RECOMMENDATIONS` catalog directly - **no `getSnapshot()`, no tenant lookup at all** |

## `query_data_protection_recommendations` (added 2026-09-22)
The one tool that breaks the pattern above: it takes no `tenantId`, because it queries [[Data Protection (DLP & Sensitivity Labels)]]'s static guidance catalog (`src/lib/data/data-protection-recommendations.ts`), never a real tenant's actual DLP/label configuration. Filters: `regulation`, `dataCategory`, `minimumLicenseTier` (returns a lightweight summary list), or `recommendationId` (returns full detail for one entry, including its generated PowerShell script materialized with a generic `"YourTenantName"` placeholder, since there's no real tenant in scope). Logs with `tenantId: undefined` in the audit trail - `executeMcpTool`'s wrapper already handles that gracefully, and this is the first tool call in that log that was never about any tenant. Verified live via the playground: filtering by `regulation: "popia"` returns the correct 6 tagged entries; `recommendationId` returns full detail correctly.

Surfaced interactively in the UI via [[MCP Tools Playground]].

Part of [[Clarity365 MOC]]. This is Clarity365's own bridge to exactly the kind of agent workflow this vault exists to support :  see [[Prompting & Obsidian Workflow]].
