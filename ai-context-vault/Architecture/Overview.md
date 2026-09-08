---
tags: [architecture]
---

# Architecture Overview

Clarity365 is a Next.js 14 App Router app, single-process, bound to `127.0.0.1` only. There is no separate backend :  API routes under `src/app/api/` *are* the backend, calling straight into `src/lib/services/`.

## The shape of the dependency graph
```
UI (24 modules, 2 dashboards) ──▶ AppShell (hub) ──▶ fetch() ──▶ API routes
                                                                     │
                                                                     ▼
                                                            Tenant Store (SQLite)
                                                          ↗        │         ↖
                                          Core Graph Layer   Fleet Ops   Analysis & Generation
                                          (Graph/EXO calls)  (sits above  (drift/compliance/
                                                 │            the store)   fleet/report/remediation)
                                                 ▼
                                    Data Mappers + Baseline Matchers
                                       (pure functions, fully tested)
```

Two god objects sit at the center, per [[Domain Types]] and [[Tenant Store]]:
- **`TenantSecuritySnapshot`** (data) :  nearly every module reads a slice of it
- **`tenant-store.ts`** (code) :  nearly every route calls into it

[[Fleet Operations]] is the one notable inversion: it imports Tenant Store rather than the reverse, because bulk/cross-tenant actions need to orchestrate many snapshots at once.

## Request lifecycle (a typical write)
1. User clicks an action in a [[Clarity365 MOC#Modules|module]] (e.g. "Deploy CA01")
2. Module opens a [[Modals|confirmation modal]], then calls `fetch()` on an API route
3. Route handler calls [[Tenant Store]] (or [[Fleet Operations]] for fleet-wide actions)
4. Tenant Store calls [[Core Graph Layer]] to make the live Graph/EXO write, or (in `mock` `authMode`) mutates the in-memory/SQLite snapshot directly
5. Tenant Store logs the action to the audit table ([[Audit Log Viewer]]) and persists to `data/clarity365.db`
6. Response flows back; module re-renders from the updated snapshot

See also [[Data Flow]], [[Security & Auth]], [[Tech Stack]].

Part of [[Clarity365 MOC]].
