# Clarity365: Multi-Tenant M365 IRM & Security Posture Suite

Clarity365 is an enterprise-grade Information Rights Management (IRM) and Security Posture dashboard built for Managed Service Providers (MSPs) and internal IT security teams managing multiple Microsoft 365 tenants.

Designed following strict, high-density sysadmin and cybersecurity principles (inspired by Bloomberg terminals and Dieter Rams), Clarity365 avoids aesthetic fluff and delivers immediate, actionable cloud security intelligence — backed by live Microsoft Graph data, not just point-in-time reports.

---

## Key Capabilities

* **Multi-Tenant Engine & Hot-Swapping** — A persistent global tenant switcher supports live Azure App Registrations (Microsoft Graph SDK & Exchange REST) alongside four built-in demo tenants (**Contoso E5**, **Northwind Business Premium**, **Fabrikam E3**, and **Woodgrove Zero-Trust**) for evaluation without real credentials.
* **Live Graph Sync** — Manual "Sync Tenant" and a background auto-sync scheduler pull real data via Microsoft Graph with resilient retry/backoff on throttling (HTTP 429/503), per-request timeouts, and pagination across large tenants.
* **Sync Health Transparency** — Partial sync failures surface as specific warnings rather than silent fallbacks; total sync failures report as errors with stale data clearly labeled, and every sync failure is recorded in the Audit Log.
* **Executive Overview Dashboard** — Six priority widgets in one view: Microsoft Secure Score (with 30/90-day deltas and industry benchmarks), live critical sign-in event stream, identity & asset matrix, license/capability detection matrix (Entra ID P1/P2, Intune, Defender for Endpoint, Defender for Office 365), Conditional Access baseline health gauge (CA01–CA10), and high-risk threat indicators.
* **24 Specialized Modules** — 15 tenant-scoped security audits, 5 cross-tenant fleet modules, 2 compliance & executive reporting engines, and 2 operational tools.
* **In-House Model Context Protocol (MCP) Server** — Exposes 8 tools for external AI agents and SOC automation (`list_tenants`, `get_tenant_secure_score`, `audit_conditional_access`, `query_signin_logs`, `audit_mfa_methods`, `audit_email_forwarding`, `manage_tabl`, `generate_remediation_plan`), complete with an interactive in-app MCP Tools Playground.
* **Obsidian-First Architectural Map** — A complete Obsidian knowledge vault (`ai-context-vault/`) maps architecture, domain models, service layers, API endpoints, and optimization backlogs.
* **Operator Authentication** — A single-operator password gate (first-run setup flow, HMAC-SHA256 signed session cookies, 12-hour TTL) protects the app via Next.js Edge middleware.
* **Encrypted Secrets at Rest** — Tenant client secrets and tokens are encrypted with AES-256-GCM before storage; operator passwords are hashed with `scrypt`. Sensitive values are never transmitted to the browser unmasked.
* **SQLite-Backed Storage** — Database persistence powered by `better-sqlite3` in WAL mode (`data/clarity365.db`) with automatic legacy JSON store migration and graceful shutdown handling.
* **High-Density Terminal Aesthetic** — Clean dark/light theme toggle, non-destructive table row hover outlining, collapsible sidebar, and one-click CSV exports.
* **Local Security Isolation** — Binds strictly to `127.0.0.1:3000` (localhost only) by default, whether run natively or via Docker.

---

## Security & Posture Modules

### Tenant-Scoped Security Audits
| # | Module | What it Audits & Remediates |
|---|--------|-----------------------------|
| 1 | **Conditional Access Policy Baseline** | Structural matching of deployed CA policies against the CA01–CA10 baseline; flags missing policies and report-only modes; one-click deployment in Report-Only mode. |
| 2 | **Sign-In Logs & CA Diagnostics** | Real-time sign-in event stream with error-code translation, CA policy rule-chain inspection, Sentinel/Defender KQL query generation, and CSV export. |
| 3 | **Secure Score & Historical Timeline** | Defender Secure Score history (30/90 days), category breakdowns, and prioritized improvement actions with remediation guidance. |
| 4 | **MFA Enforcement & Auth Audit** | Per-user authentication method classification (Passkey/FIDO2, Microsoft Authenticator push/TOTP, SMS, voice, email OTP); flags weak MFA and highlights licensed accounts missing MFA with dedicated tags and filter views. |
| 5 | **User & Account Classification** | Licensed, unlicensed-active (orphan risk), disabled, and guest account breakdowns; detects privileged accounts carrying daily-use licenses. |
| 6 | **Privileged Access Review** | Directory admin inventory, admin role assignments, auth method strengths, and least-privilege benchmarks; identifies unprotected privileged accounts. |
| 7 | **Exchange Mailbox Permissions** | Live Full Access / Send As / Send on Behalf delegation audit, licensed-shared-mailbox waste detection, mailbox auditing status check, and one-click delegation revocation. |
| 8 | **Email Forwarding Rules Audit** | Live transport rules, inbox rules (including hidden rules), and SMTP forwarding; critical alerts for external targets with one-click remediation. |
| 9 | **Mailflow Rules & Transport Hygiene** | Evaluates transport rules and connectors against known abuse patterns (external redirects, spam bypasses, open connectors, missing TLS); one-click baseline remediation. |
| 10 | **Defender for Office 365 (MDO) & TABL** | Threat policy review (Anti-Phish, Safe Attachments, Safe Links) plus an interactive Tenant Allow/Block List manager (domains, senders, URLs, file hashes). |
| 11 | **Domain Authentication (SPF / DKIM / DMARC)** | Live DNS validation for SPF, DKIM (Exchange Online status), and DMARC records per accepted domain with exact DNS record publication guidance. |
| 12 | **Enterprise Apps & App Registrations** | High-privilege Graph API scopes, credentials expiring within 30/60/90 days, and expired app secrets. |
| 13 | **Intune Endpoint Security** | Device compliance, antivirus, and EDR onboarding status across Windows, macOS, and Linux endpoints. |
| 14 | **Groups & Distribution Management** | Security groups, Microsoft 365 Unified groups, and distribution lists with role-assignable group tracking and interactive creation. |
| 15 | **SharePoint & Storage Policies** | Tenant-wide sharing tiers, anonymous link expiration policies, and per-site storage quota tracking. |

### Fleet-Scale Operations (Cross-Tenant)
| # | Module | Fleet Capability |
|---|--------|------------------|
| 16 | **Fleet Baseline Rollout** | Multi-tenant CA policy deployment orchestrator; preview and execute CA01–CA10 baselines across multiple client tenants simultaneously. |
| 17 | **Fleet Baseline Drift** | Automated drift detection across all managed tenants against Golden Baseline templates, with one-click drift realignment. |
| 18 | **Fleet TABL Sync** | Cross-tenant Tenant Allow/Block List synchronization; deploy threat indicators across the entire client fleet. |
| 19 | **Fleet License Optimization** | Fleet-wide license waste detection (orphaned licenses, disabled user seats, licensed shared mailboxes) with monthly cost-savings calculations. |
| 20 | **Tenant License Optimization** | Single-tenant license waste analyzer with reclamation steps. |

### Reporting, Compliance & Incident Operations
| # | Module | Capability |
|---|--------|------------|
| 21 | **Executive Reporting (QBR)** | Client-ready Quarterly Business Review security report generator with health scoring, cost savings, achievements, and printable export. |
| 22 | **Compliance Matrix** | Multi-framework compliance scoring across **CIS Microsoft 365 Benchmark v3**, **NIST CSF v2**, and **Essential 8**. |
| 23 | **Event Response (Incident Response)** | Incident management with MITRE ATT&CK mapping; rapid remediation actions (contain user account, isolate endpoint device, trigger Defender scan). |
| 24 | **Audit Log & MCP Playground** | Searchable audit trail of all mutating actions, policy deployments, and sync events; interactive testing workbench for the 8 MCP tools. |

---

## Tech Stack

* **Framework:** Next.js 14 (App Router), React 18, TypeScript 5.5
* **Styling:** Tailwind CSS 3 (class-based dark mode, high-density terminal grid styling)
* **Storage:** better-sqlite3 13 (WAL mode) with automated JSON store migration
* **Security:** Web Crypto (Edge-safe HMAC-SHA256), Node crypto (AES-256-GCM, scrypt)
* **Testing:** Vitest 4 (25 suites, 287 unit tests)
* **Deployment:** Docker (multi-stage `node:20-alpine`) or standalone Node process

---

## AI Context & Obsidian Vault

Clarity365 includes a built-in Obsidian Knowledge Vault located in [`ai-context-vault/`](ai-context-vault).

- **Map of Content:** Start at [`ai-context-vault/Clarity365 MOC.md`](ai-context-vault/Clarity365%20MOC.md) to navigate architecture, services, data types, and modules.
- **Agent Directives:** Guidelines for AI pair programming are documented in [`AGENTS.md`](AGENTS.md), [`GEMINI.md`](GEMINI.md), and [`CLAUDE.md`](CLAUDE.md).
- **Obsidian MCP Integration:** Supports `obsidian-mcp-rs` to allow AI coding assistants to directly query and maintain vault notes.

---

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment Secrets
Clarity365 requires two secrets before starting. Copy `.env.example` and generate secure 32-byte hex keys:
```bash
cp .env.example .env.local
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # run twice
```
Set the generated values in `.env.local`:
```env
CLARITY365_SESSION_SECRET=<first-generated-secret>
CLARITY365_ENCRYPTION_KEY=<second-generated-secret>
```
> **Important:** `CLARITY365_ENCRYPTION_KEY` encrypts live tenant credentials at rest. Store these keys securely in a password manager. Changing the encryption key later will render existing stored secrets unreadable.

### 3. Run Development Server
```bash
npm run dev
```
Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)**. On first run, you will be prompted to create the operator password used to sign in.

### 4. Production Build & Start
```bash
npm run build
npm start
```

### 5. Docker Deployment
```bash
docker-compose up --build
```

### Other Scripts
```bash
npm run stop         # frees port 3000 (graceful SIGTERM, then force kill)
npm run restart      # stops existing process and restarts dev server
npm run type-check   # tsc --noEmit
npm test             # vitest run (executes all 25 test suites)
npm run lint         # next lint
```

---

## Security & Privacy Invariants

* **Zero Internet Exposure:** The server binds strictly to `127.0.0.1:3000` by default.
* **Single-Operator Auth:** Every route is gated behind Edge middleware validating an HMAC-signed session cookie.
* **Zero Plaintext Secrets:** Tenant secrets are encrypted with AES-256-GCM before writing to SQLite and are never sent unmasked to the browser.
* **Audit Trail:** Every mutating action (CA policy deployment, mailbox delegation revocation, incident containment, MCP execution) is persisted to the local audit log.
