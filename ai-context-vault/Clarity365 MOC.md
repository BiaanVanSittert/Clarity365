---
tags: [moc]
---

# Clarity365 — AI Context Map

Multi-Tenant M365 IRM & Security Posture Suite for MSPs & Enterprise IT. This vault is a hand-built knowledge map of the codebase as of `f97226a` (2026-09-08) — 24 modules, 33 API routes, ~30 services, one SQLite-backed store. Open Obsidian's **Graph View** on this vault to see it as a mindmap; colors are grouped by tag (module / service / architecture / api / data-model / mcp / optimization / recommendation).

Start here, then follow links outward — every note links back to this one, so you can never get lost.

## Architecture
[[Overview]] · [[Tech Stack]] · [[Data Flow]] · [[Security & Auth]] · [[Testing]]

## Data model
[[Domain Types]] — the `TenantSecuritySnapshot` god object and everything hanging off it
[[Baseline Definitions & Mock Data]] — the 39 baseline rules (CA/MDO/Mailflow/Groups/SharePoint) and the demo dataset

## Services (the backbone)
[[Tenant Store]] — the god service everything calls
[[Core Graph Layer]] · [[Baseline Matchers]] · [[Data Mappers]] · [[Analysis & Generation]] · [[Fleet Operations]] · [[Security Infra]]

## API & MCP
[[API Surface]] — all 33 routes
[[MCP Server]] — 8 agent-facing tools

## UI
[[AppShell]] — the shell every module renders through
[[Overview Dashboard]] · [[Modals]] · [[Common Components]]

## Modules
**Tenant-scoped security modules:**
[[Conditional Access Policy Scanner]] · [[Sign-In Logs & CA Diagnostics]] · [[Secure Score & Timeline]] · [[MFA Enforcement & Auth Audit]] · [[User & Account Classification]] · [[Privileged Access Review]] · [[Exchange Mailbox Permissions]] · [[Email Forwarding Rules Audit]] · [[Mailflow Rules & Transport Hygiene]] · [[Defender for Office 365 & TABL]] · [[App Registrations & Connected Services]] · [[Intune Endpoint Security]] · [[Groups & Distribution Management]] · [[SharePoint & Storage Policies]] · [[Domain Authentication]]

**System & agent-facing:**
[[Audit Log Viewer]] · [[MCP Tools Playground]] · [[Event Response (Incident Response)]]

**Reporting & compliance:**
[[Executive Reporting (QBR)]] · [[Compliance Matrix (CIS-NIST-Essential 8)]]

**Fleet-scale (cross-tenant):**
[[Fleet Baseline Rollout]] · [[Fleet Baseline Drift]] · [[Fleet TABL Sync]] · [[Fleet License Optimization]] · [[Tenant License Optimization]]

## Where this goes next
[[Optimization Plan]] — prioritized findings from this scan (security gaps, test coverage, structural risk)
[[Prompting & Obsidian Workflow]] — how to prompt Claude Code against this vault, and how to keep the vault from going stale

## A note on repo history
This vault was built immediately after discovering the local working copy was **203 commits behind `origin/main`** — an entire auth system, fleet operations layer, incident response, compliance frameworks, and executive reporting existed on GitHub but not in the checked-out code. The repo was fast-forwarded to match before this scan ran, so everything above reflects the current, real state of the app — not the stale one. See [[Optimization Plan]] for how to stop this from recurring silently.
