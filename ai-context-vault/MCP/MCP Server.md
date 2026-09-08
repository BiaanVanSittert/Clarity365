---
tags: [mcp]
---

# MCP Server

In-house Model Context Protocol server exposing 8 tools for AI agents / local SOC automation. `src/lib/mcp/definitions.ts` (schemas) + `src/lib/mcp/engine.ts` (`executeMcpTool`, wraps every call in [[Audit Log Viewer|audit logging]] regardless of outcome), served via `POST /api/mcp`.

| Tool                        | Calls                                                                                                                                             |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `list_tenants`              | [[Tenant Store]] `getAllTenants()` + `getSnapshot()` per tenant                                                                                   |
| `get_tenant_secure_score`   | `getSnapshot()` → reads `secureScore`                                                                                                             |
| `audit_conditional_access`  | `getSnapshot()` → reads pre-computed `conditionalAccess` (no live matcher call)                                                                   |
| `query_signin_logs`         | `getSnapshot()` → filters `signIns`                                                                                                               |
| `audit_mfa_methods`         | `getSnapshot()` → filters `mfaAudit`                                                                                                              |
| `audit_email_forwarding`    | `getSnapshot()` → reads `emailForwarding`                                                                                                         |
| `manage_tabl`               | `getSnapshot()` (list) / `addTablEntry()` / `removeTablEntry()` — **the only tool with a write path**, gated behind `Settings.allowToolExecution` |
| `generate_remediation_plan` | `getSnapshot()` + [[Analysis & Generation]]'s `remediation-generator.generateRemediationPlanForTenant()`                                          |

Surfaced interactively in the UI via [[MCP Tools Playground]].

Part of [[Clarity365 MOC]]. This is Clarity365's own bridge to exactly the kind of agent workflow this vault exists to support — see [[Prompting & Obsidian Workflow]].
