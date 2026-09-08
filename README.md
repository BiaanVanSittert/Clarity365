# Clarity365: Multi-Tenant M365 IRM and Security Posture Suite

Clarity365 is an enterprise Information Rights Management and Security Posture dashboard built for Managed Service Providers and internal IT security teams managing multiple Microsoft 365 tenants.

Built on high-density sysadmin principles with inspiration from terminal interfaces and industrial design, Clarity365 delivers live cloud security intelligence backed directly by Microsoft Graph data rather than static point-in-time exports.

## Core Capabilities

* **Multi-Tenant Architecture:** Persistent global tenant switcher supporting live Azure App Registrations (Microsoft Graph SDK and Exchange REST) alongside four built-in demo tenants (Contoso E5, Northwind Business Premium, Fabrikam E3, and Woodgrove Zero-Trust) for evaluation without production credentials.
* **Live Graph Synchronization:** Manual sync and background auto-sync scheduler pull data through Microsoft Graph with retry backoff for HTTP 429 and 503 responses, per-request timeouts, and paging across large tenants.
* **Sync Health Visibility:** Partial sync failures surface as specific warnings rather than silent fallbacks. Complete sync failures report as errors with stale data explicitly labeled, and every sync event persists to the audit log.
* **Executive Overview:** Six widgets in one view: Microsoft Secure Score with 30-day and 90-day deltas, live critical sign-in event stream, identity matrix, license detection matrix (Entra ID P1/P2, Intune, Defender for Endpoint, Defender for Office 365), Conditional Access baseline health gauge covering CA01 through CA10, and high-risk threat indicators.
* **24 Specialized Security Modules:** 15 tenant-scoped security audits, 5 cross-tenant fleet modules, 2 compliance and executive reporting engines, and 2 operational tools.
* **Model Context Protocol Server:** Built-in MCP server exposing 8 tools for external AI agents and SOC automation (`list_tenants`, `get_tenant_secure_score`, `audit_conditional_access`, `query_signin_logs`, `audit_mfa_methods`, `audit_email_forwarding`, `manage_tabl`, `generate_remediation_plan`), complete with an interactive in-app workbench.
* **Obsidian Architecture Vault:** Complete Obsidian knowledge vault (`ai-context-vault/`) mapping application architecture, domain models, service layers, API endpoints, and optimization plans.
* **Operator Authentication:** Single-operator password gate with first-run setup flow, HMAC-SHA256 signed session cookies, and 12-hour TTL enforced at the Next.js Edge middleware layer.
* **Encrypted Secrets at Rest:** Tenant credentials and tokens are encrypted with AES-256-GCM before storage. Operator passwords use scrypt hashing. Secrets are never exposed to the client unmasked.
* **SQLite Persistence:** Powered by `better-sqlite3` in WAL mode (`data/clarity365.db`) with automatic migration from legacy JSON stores and graceful process shutdown.
* **High-Density Terminal Interface:** Dark and light theme toggle, non-destructive table row hover highlighting, collapsible navigation sidebar, and CSV export across data tables.
* **Local Security Isolation:** Binds strictly to `127.0.0.1:3000` (localhost only) by default, both in native execution and Docker containers.

## Security and Posture Modules

### Tenant-Scoped Audits

| # | Module | Scope and Capabilities |
|---|--------|------------------------|
| 1 | **Conditional Access Policy Baseline** | Structural matching of deployed CA policies against baseline policies CA01 through CA10. Flags missing policies, identifies report-only modes, and provides one-click deployment in report-only mode. |
| 2 | **Sign-In Logs and CA Diagnostics** | Real-time sign-in event stream with error code translation, CA policy rule-chain inspection, Sentinel/Defender KQL query generation, and CSV export. |
| 3 | **Secure Score and Historical Timeline** | Defender Secure Score history across 30-day and 90-day periods, category breakdowns, and prioritized improvement actions with remediation guidance. |
| 4 | **MFA Enforcement and Auth Audit** | Per-user authentication method classification (Passkey/FIDO2, Microsoft Authenticator push or TOTP, SMS, voice, email OTP). Identifies weak auth methods and flags licensed accounts lacking MFA with dedicated badges and filter toggles. |
| 5 | **User and Account Classification** | Categorizes accounts into licensed, unlicensed active (orphan risk), disabled, and guest tiers. Flags privileged accounts consuming daily-use licenses. |
| 6 | **Privileged Access Review** | Directory admin inventory, admin role assignments, auth method strengths, and least-privilege benchmarks. Highlights unprotected privileged accounts. |
| 7 | **Exchange Mailbox Permissions** | Live Full Access, Send As, and Send on Behalf delegation audit. Detects licensed shared mailbox waste, validates mailbox audit logging, and revokes delegations in one click. |
| 8 | **Email Forwarding Rules Audit** | Live transport rules, inbox rules including hidden rules, and SMTP forwarding targets. Emits critical alerts for external forwarding targets with one-click removal. |
| 9 | **Mailflow Rules and Transport Hygiene** | Evaluates transport rules and connectors against abuse patterns (external redirects, spam filter bypasses, open connectors, missing TLS). Provides one-click baseline remediation. |
| 10 | **Defender for Office 365 and TABL** | Threat policy review (Anti-Phish, Safe Attachments, Safe Links) combined with an interactive Tenant Allow/Block List manager for domains, senders, URLs, and file hashes. |
| 11 | **Domain Authentication (SPF, DKIM, DMARC)** | Live DNS validation for SPF, DKIM (Exchange Online signing status), and DMARC records per accepted domain, including exact DNS record syntax guidance. |
| 12 | **Enterprise Apps and App Registrations** | Flags high-privilege Graph API scopes, credentials expiring within 30, 60, or 90 days, and expired app secrets. |
| 13 | **Intune Endpoint Security** | Validates device compliance, antivirus status, and EDR onboarding across Windows, macOS, and Linux endpoints. |
| 14 | **Groups and Distribution Management** | Tracks security groups, Microsoft 365 Unified groups, and distribution lists with role-assignable group tracking and group provisioning. |
| 15 | **SharePoint and Storage Policies** | Tenant-wide sharing tiers, anonymous link expiration policies, and per-site storage quota tracking. |

### Fleet-Scale Operations (Cross-Tenant)

| # | Module | Fleet Capability |
|---|--------|------------------|
| 16 | **Fleet Baseline Rollout** | Multi-tenant CA policy deployment orchestrator. Previews and deploys CA01 through CA10 baselines across multiple client tenants simultaneously. |
| 17 | **Fleet Baseline Drift** | Automated drift detection across all managed tenants against Golden Baseline templates, with one-click drift realignment. |
| 18 | **Fleet TABL Sync** | Cross-tenant Tenant Allow/Block List synchronization to deploy threat indicators across the entire managed tenant fleet. |
| 19 | **Fleet License Optimization** | Cross-tenant license waste detection (orphaned licenses, disabled user seats, licensed shared mailboxes) with monthly cost savings calculations. |
| 20 | **Tenant License Optimization** | Single-tenant license waste analyzer with step-by-step reclamation guidance. |

### Reporting, Compliance, and Incident Operations

| # | Module | Capability |
|---|--------|------------|
| 21 | **Executive Reporting (QBR)** | Client-ready Quarterly Business Review security report generator with posture scoring, cost savings metrics, key achievements, and printable export. |
| 22 | **Compliance Matrix** | Multi-framework compliance scoring across CIS Microsoft 365 Benchmark v3, NIST CSF v2, and Essential 8. |
| 23 | **Event Response (Incident Response)** | Incident management with MITRE ATT&CK mapping and rapid remediation actions (contain user account, isolate endpoint device, trigger Defender scan). |
| 24 | **Audit Log and MCP Playground** | Searchable audit trail of all mutating actions, policy deployments, and sync events, alongside an interactive testing workbench for all 8 MCP tools. |

## Technology Stack

* **Framework:** Next.js 14 (App Router), React 18, TypeScript 5.5
* **Styling:** Tailwind CSS 3 (class-based dark mode, high-density terminal grid styling)
* **Storage:** better-sqlite3 13 (WAL mode) with automated JSON store migration
* **Security:** Web Crypto (Edge-safe HMAC-SHA256), Node crypto (AES-256-GCM, scrypt)
* **Testing:** Vitest 4 (25 suites, 287 unit tests)
* **Deployment:** Docker (multi-stage `node:20-alpine`) or standalone Node process

## Obsidian Context Vault

Clarity365 includes a structured Obsidian Knowledge Vault located in [`ai-context-vault/`](ai-context-vault).

* **Map of Content:** [`ai-context-vault/Clarity365 MOC.md`](ai-context-vault/Clarity365%20MOC.md) indexes architecture, services, data types, and modules.
* **Agent Directives:** Pairing guidelines are documented in [`AGENTS.md`](AGENTS.md), [`GEMINI.md`](GEMINI.md), and [`CLAUDE.md`](CLAUDE.md).
* **Obsidian MCP Integration:** Supports `obsidian-mcp-rs` to allow AI coding assistants to directly query and maintain vault notes.

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Secrets

Clarity365 requires two secrets before starting. Copy `.env.example` and generate secure 32-byte hex keys:

```bash
cp .env.example .env.local
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
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

### 4. Production Build and Start

```bash
npm run build
npm start
```

### 5. Docker Deployment

```bash
docker-compose up --build
```

### Available Scripts

* `npm run stop` : terminates processes on port 3000
* `npm run restart` : restarts development server
* `npm run type-check` : runs TypeScript compiler checks without emitting files
* `npm test` : runs Vitest suite (25 test files, 287 unit tests)
* `npm run lint` : runs Next.js linter

## Security and Privacy Invariants

* **Zero Internet Exposure:** The server binds strictly to `127.0.0.1:3000` by default.
* **Single-Operator Auth:** Every route is gated behind Edge middleware validating an HMAC-signed session cookie.
* **Zero Plaintext Secrets:** Tenant secrets are encrypted with AES-256-GCM before writing to SQLite and are never sent unmasked to the browser.
* **Audit Trail:** Every mutating action (CA policy deployment, mailbox delegation revocation, incident containment, MCP execution) is persisted to the local audit log.
