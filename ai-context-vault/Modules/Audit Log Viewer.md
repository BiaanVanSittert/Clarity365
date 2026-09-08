---
tags: [module, security]
---

# Audit Log Viewer

Cross-tenant system audit log :  every mutating action the app itself performs, across all modules and the MCP server.

- **Component:** `AuditLogModule.tsx`
- **API routes:** `GET /api/audit-log?{params}`
- **Key types:** `AuditLogEntry` :  see [[Domain Types]]
- **Renders:** `StatusPill`, `Pagination`, `EmptyStateRow`
- **Written by:** [[Tenant Store]] on every mutation, and by [[MCP Server]]'s `executeMcpTool` wrapper (every tool call is logged regardless of outcome)

Part of [[Clarity365 MOC]]. This is the app's own accountability trail :  see [[Security & Auth]].
