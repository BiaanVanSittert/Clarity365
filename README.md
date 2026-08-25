# Clarity365: Multi-Tenant M365 IRM & Security Posture Suite

Clarity365 is an enterprise-grade Information Rights Management (IRM) and Security Posture dashboard built for Managed Service Providers (MSPs) and internal IT security teams managing multiple Microsoft 365 tenants.

Designed following strict, high-density sysadmin and cybersecurity principles (inspired by Bloomberg terminals and Dieter Rams), Clarity365 avoids aesthetic fluff and delivers immediate, actionable cloud security intelligence — backed by live Microsoft Graph data, not just point-in-time reports.

---

## Key Capabilities

* **Multi-Tenant Engine & Hot-Swapping** — A persistent global tenant switcher supports live Azure App Registrations (Microsoft Graph SDK & Exchange REST) alongside four built-in demo tenants for evaluation without any real credentials.
* **Live Graph Sync** — Manual "Sync Tenant" and a background auto-sync scheduler (configurable interval) pull real data via Microsoft Graph, with resilient retry/backoff on throttling (HTTP 429/503), per-request timeouts, and pagination across large tenants.
* **Sync Health Transparency** — Partial sync failures (e.g. one endpoint unreachable due to a missing permission) surface as a specific warning rather than a silent fallback; a total sync failure is reported as an error with the last-known-good data clearly labeled as stale, and every sync failure is recorded in the Audit Log.
* **Executive Overview Dashboard** — Six priority widgets in one screen: Microsoft Secure Score (with 30/90-day deltas and industry benchmark), a live critical sign-in event stream, an identity & asset count matrix, a license/capability detection matrix (Entra ID P1/P2, Intune, Defender for Endpoint, Defender for Office 365), a Conditional Access baseline health gauge (CA01–CA10), and high-risk threat indicators.
* **14 Security Modules** — see the full list below.
* **In-House Model Context Protocol (MCP) Server** — exposes 8 tools for AI agents and SOC automation, with an interactive in-app Playground to test calls before wiring up an external agent.
* **Operator Authentication** — a single-operator password gate (first-run setup flow, HMAC-signed session cookies, 12-hour sessions) protects the whole app via Next.js middleware.
* **Encrypted Secrets at Rest** — tenant client secrets are encrypted with AES-256-GCM before being written to disk; operator passwords are hashed with scrypt. Nothing sensitive is ever sent back to the browser unmasked.
* **SQLite-Backed Storage** — tenant configuration, snapshots, settings, and the audit log live in a local SQLite database (WAL mode) under `data/`, with automatic migration from the legacy flat-file JSON store and a graceful connection close on shutdown.
* **Reliability Hardening** — per-module React error boundaries (a crash in one module never takes down the rest of the app), lazy-loaded modules for a smaller initial bundle, request timeouts on all Graph calls, and audit-logged sync failures.
* **Dark Mode & Collapsible Sidebar** — a persisted, flicker-free dark/light theme toggle and a collapsible icon-rail sidebar for a denser working view.
* **CSV Export** — one-click export of filtered table data (sign-in logs, MFA audit, audit log, and more) for reporting or ticket attachments.
* **Local Security Isolation** — binds strictly to `127.0.0.1:3000` by default (localhost only, not exposed to LAN/WAN) whether run directly or via Docker.

---

## Security Modules

| # | Module | What it audits |
|---|--------|-----------------|
| 1 | **Conditional Access Policy Baseline** | Structural matching of deployed CA policies against the CA01–CA10 industry baseline; flags missing policies and report-only-mode configurations; one-click deploy of missing baselines in Report-Only mode. |
| 2 | **Sign-In Logs & CA Diagnostic Engine** | Real-time sign-in event stream with error-code translation, CA policy rule-chain inspection, KQL query generation for Sentinel/Defender, and CSV export. |
| 3 | **Defender Secure Score & Historical Timeline** | Score trend over time, category breakdown, and categorized improvement actions with remediation guidance. |
| 4 | **MFA Enforcement & Auth Methods Audit** | Per-user authentication method classification (Passkey/FIDO2, Microsoft Authenticator push/TOTP, SMS, voice, email OTP), flags weak or missing MFA, CSV export. |
| 5 | **User & Account Classification** | Licensed, unlicensed-active (orphan risk), disabled, and guest account breakdowns. |
| 6 | **Exchange Mailbox Permissions & Delegation** | Full Access / Send As delegation audit and licensed-shared-mailbox cost waste detection. |
| 7 | **Email Forwarding Rules Audit** | Transport rules, inbox rules, and SMTP forwarding addresses, with critical alerts for external-domain targets. |
| 8 | **Defender for Office 365 (MDO) & TABL Manager** | Threat policy review plus an interactive Tenant Allow/Block List editor (domains, senders, URLs, file hashes). |
| 9 | **Enterprise Apps & App Registrations** | High-privilege Graph API scopes and expiring/expired credentials across app registrations. |
| 10 | **Intune Endpoint Security** | Fleet antivirus and EDR onboarding coverage across Windows/macOS/Linux devices. |
| 11 | **Microsoft Groups & Distribution Management** | Security groups, Microsoft 365 Unified groups, and distribution lists, with an interactive group creator. |
| 12 | **SharePoint & Storage Policies** | Storage quota tracking and external sharing tier management. |
| 13 | **MCP Tools & Playground** | Interactively invoke any of the 8 MCP tools against a live or demo tenant and inspect the JSON response. |
| 14 | **Audit Log** | Searchable, filterable record of CA policy deployments, MCP tool calls, and sync failures across all tenants, with CSV export. |

---

## Tech Stack

* **Framework:** Next.js 14 (App Router), React 18, TypeScript
* **Styling:** Tailwind CSS (class-based dark mode)
* **Storage:** better-sqlite3 (WAL mode), with automatic legacy JSON migration
* **Testing:** Vitest
* **Deployment:** Docker (multi-stage, `node:20-alpine`) or a plain Node.js process

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment secrets
Clarity365 needs two secrets before it will start — copy the example file and generate real values:
```bash
cp .env.example .env.local
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # run twice
```
Paste the two generated values into `.env.local` as `CLARITY365_SESSION_SECRET` and `CLARITY365_ENCRYPTION_KEY`. `.env.local` is gitignored and must never be committed. (`CLARITY365_ENCRYPTION_KEY` derives the key that encrypts live tenant client secrets at rest — changing it later makes previously-stored secrets unreadable.)

### 3. Run the local development server
```bash
npm run dev
```
Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)** in your browser. On first run you'll be prompted to create the operator password used to sign in — there's no default credential.

### 4. Production build
```bash
npm run build
npm start
```

### 5. Single-command Docker deployment
```bash
docker-compose up --build
```
Set `CLARITY365_SESSION_SECRET` and `CLARITY365_ENCRYPTION_KEY` in `.env.local` first — `docker-compose.yml` loads it via `env_file`.

### Other scripts
```bash
npm run stop         # frees port 3000 (graceful stop, then force-kill any survivor)
npm run restart      # stop, then start the dev server
npm run type-check   # tsc --noEmit
npm test             # run the Vitest suite
npm run lint         # next lint
```

---

## Getting Started In-App

1. Sign in with the operator password you created on first run (or add a tenant right away — four demo tenants, Contoso, Northwind, Fabrikam, and Woodgrove, are seeded automatically for evaluation with no credentials required).
2. To connect a real tenant, add an Azure App Registration with the required Microsoft Graph application permissions, then use **Add New Tenant** → the built-in **Permissions** check confirms every required scope is granted before you rely on the data.
3. Use **Sync Tenant** to pull live data on demand, or configure an auto-sync interval in **Settings** to keep tenants refreshed in the background.

---

## Security & Privacy Note

Clarity365 is designed around zero-trust and least-exposure principles for a tool that holds sensitive tenant credentials:

* The entire app sits behind a single-operator login (Next.js middleware gate); there is no default password.
* Live tenant client secrets are encrypted at rest with AES-256-GCM and are never returned to the browser unmasked.
* The operator password is hashed with scrypt, never stored or logged in plaintext.
* The server binds strictly to `127.0.0.1` by default — not exposed to your LAN or the internet unless you deliberately change the bind address.
* All mutating actions (CA policy deployments, MCP tool calls, sync failures) are recorded to a local, retention-pruned audit log.
