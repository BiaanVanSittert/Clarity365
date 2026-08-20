# Clarity365 — Multi-Tenant M365 IRM & Security Posture Suite

Clarity365 is an enterprise-grade Information Rights Management (IRM) and Security Posture dashboard package built for Managed Service Providers (MSPs) and internal IT security teams.

Designed following strict, high-density sysadmin principles (inspired by Bloomberg terminals and Dieter Rams), Clarity365 avoids aesthetic fluff and delivers immediate, actionable cloud security intelligence across all Microsoft 365 customer tenants.

---

## Key Architectural Capabilities

* **Multi-Tenant Engine & Tenant Hot-Swapping:** Persistent global tenant switcher supporting live Azure App Registrations (Microsoft Graph SDK & Exchange REST) alongside instant simulation datasets.
* **Top 6 Priority Overview Widgets:**
  1. Microsoft Secure Score Card (Score, 30/90-day deltas, benchmark comparison)
  2. Real-Time Critical Security & Sign-In Log Streamer
  3. Identity & Asset Count Matrix (Licensed, Unlicensed Active Orphan Risk, Shared Mailbox, Intune Devices)
  4. Tenant License & Capability Detection Matrix (Entra ID P1/P2, Intune, MDE, Purview, MDO)
  5. Conditional Access Baseline Health Gauge (`CA01:` through `CA10:` compliance)
  6. High-Risk Threat Indicators (External forwarding, open SharePoint links, unprotected admins)
* **12 Comprehensive Security Modules:**
  * **Module 1: Conditional Access Policy Scanner** (CA01–CA10 prefix matching, report-only detection)
  * **Module 2: Sign-In Logs & CA Diagnostic Engine** (Error code translation & rule-chain inspector)
  * **Module 3: Defender Secure Score & Historical Timeline** (90-day trajectory & categorized improvement actions)
  * **Module 4: MFA Enforcement & Auth Methods Audit** (Passkeys/FIDO2, Authenticator, weak SMS/Email OTP flags)
  * **Module 5: User & Account Classification** (Licensed, Unlicensed Active orphan risks, Disabled)
  * **Module 6: Exchange Mailbox Permissions & Delegation** (Full Access, Send As, licensed shared mailbox cost waste)
  * **Module 7: Email Forwarding Rules Audit** (Transport rules, Inbox rules, SMTP forwarding alerts)
  * **Module 8: Defender for Office 365 (MDO) & TABL Manager** (Threat policies & interactive Allow/Block list editor)
  * **Module 9: Connected Services & App Registrations** (High-privilege Graph scopes & expiring credentials)
  * **Module 10: Intune Endpoint Security** (Fleet Antivirus & EDR onboarding for Windows/macOS/Linux)
  * **Module 11: Microsoft Groups & Distribution Management** (Security, M365 Unified, DL, interactive group creator)
  * **Module 12: SharePoint & Storage Policies** (Quota bars & external sharing tier manager)
* **In-House Model Context Protocol (MCP) Server:** Exposes 8 standard tools for AI agents and local SOC automation (`list_tenants`, `get_tenant_secure_score`, `audit_conditional_access`, `query_signin_logs`, `audit_mfa_methods`, `audit_email_forwarding`, `manage_tabl`, `generate_remediation_plan`).
* **Local Security Isolation:** Strictly binds to `127.0.0.1:3000` (Localhost only, not exposed to LAN or WAN).

---

## Quick Start (Localhost Only)

### 1. Install Dependencies
```bash
npm install
```

### 2. Run Local Development Server
```bash
npm run dev
```
Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)** in your browser.

### 3. Production Build
```bash
npm run build
npm start
```

### 4. Single-Command Docker Deployment
```bash
docker-compose up --build
```

---

## Security & Privacy Note

Clarity365 is designed with Zero-Trust principles. Live client credentials and secrets are encrypted in-memory and in local configurations, bound strictly to the local host interface (`127.0.0.1`).
