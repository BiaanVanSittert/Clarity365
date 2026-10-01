---
tags: [optimization, plan, exchange]
---

# Exchange App-Only Access - Plan

Status: **Phase 0 passed and option C built, 2026-09-30.** Exchange now works through the app registration with the tenant's existing client secret (no sign-in, no certificate needed to start). The certificate is an optional later upgrade.

## Decision (user, 2026-09-30): option C, simplest possible setup
- **App-only via the existing client secret first**, falling back to the older device-code sign-in only when app-only isn't set up. A certificate becomes an optional upgrade later (Microsoft's documented method).
- **Per-tenant setup is two Entra portal steps**: add Office 365 Exchange Online → Exchange.ManageAsApp (Application) with admin consent, and assign **Exchange Administrator** (all features) or **Global Reader** (reports only) to the app.
- **Onboarding must stay short and plain.** One checklist, optional details folded away, no paragraphs of caveats.

## Built (2026-09-30)
- `src/lib/utils/exchange-access.ts` (+ test): `getExchangeAccess()`, `canWriteToExchange()`, `classifyExoAppToken()`, the one answer to "can Clarity365 use / write to Exchange for this tenant", replacing ~20 separate `exoRefreshToken` checks (4 sync gates, 9 tenant-store write gates, 5 modules, the Permissions check, the connectivity test).
- `exo-client.ts`: `getExoAppOnlyAccess()` gets an Exchange token with the client secret, decodes `roles`/`wids` to record status, role and whether it can write (cached; "not set up" re-checked after 5 minutes). `invokeExoCommand` uses app-only first, delegated second. `testExoConnectivity` reports the mode and app-only status.
- `TenantCredentials.exoAppAccess` records the result; the sync and the Permissions check save it, so every module shows the current state.
- Writes need the tenant's write switch **and** a role that can write (Exchange Administrator / Global Administrator, or the delegated sign-in). Global Reader tenants get a clear message instead of a failure at Microsoft.
- **Onboarding:** `AddTenantModal` is now a 3-step checklist (secret → API permissions incl. Exchange.ManageAsApp → assign the role), with the Graph list and optional permissions folded away. The Permissions check's Exchange section shows "Connected - no sign-in needed" plus the role, or the same two steps, with the admin sign-in behind a small "use an admin sign-in instead" link.
- Tests: `exchange-access.test.ts`, app-only cases in `exo-client.test.ts`. Verified live on Crimson Line with the app's own code and the delegated token removed in memory: connectivity, Exchange security settings (20 mailboxes), 6 MDO policies + TABL, and domains/DKIM all through app-only, matching the earlier delegated sync.

**Still to do:** writes under Exchange Administrator haven't been exercised live yet (Crimson Line has Global Reader). The first real one-click fix on an Exchange Administrator tenant is the verification. Phases 1 (certificate), 3's certificate-expiry warnings and the later items below remain optional.

## Requirement (user, 2026-09-30): no sign-in, ever
After setup, Clarity365 must reach Exchange with **no interactive sign-in of any kind**: no device code, no admin account, no Exchange PowerShell session. Setup is done once per tenant **in the Entra admin portal only**, alongside the existing app registration and Graph consent:
1. **API permission:** Office 365 Exchange Online → Exchange.ManageAsApp (Application) → Grant admin consent.
2. **Certificate:** App registration → Certificates & secrets → Upload the `.cer` Clarity365 generates for the tenant.
3. **Role on the app:** Roles and administrators → the chosen Entra role (Global Reader by default) → Add assignment → the app.

Only **Entra roles** are used, because they're assigned in the portal. Exchange's custom role groups ("Option 2" in Microsoft's doc) are **out of scope**: they need a one-time Exchange PowerShell session per tenant, which breaks this requirement. Ongoing upkeep is only certificate renewal (generate a new one in Clarity365, upload it, before the old one expires; Clarity365 warns ahead of time).

User request: modules that depend on **Connect Exchange Online** (the per-tenant device-code sign-in) should use API permissions instead, like the Graph-based modules do.

## Current state
- Every Exchange call goes through `invokeExoCommand` (`exo-client.ts`), which POSTs to Exchange's REST cmdlet endpoint (`outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand`) with a **delegated** token. That token comes from a one-time device-code sign-in with Microsoft's first-party Exchange PowerShell client, then a rotating refresh token stored encrypted (`TenantCredentials.exoRefreshToken`).
- What Clarity365 can do in Exchange is whatever the **signing-in admin** can do; it can't be narrowed. `exoWriteEnabled` is the manual substitute.
- The refresh token can be revoked, expire, or break when the admin leaves, and it rotated with a race until 2026-09-30 (see [[Core Graph Layer]]). Only 2 of 11 live tenants have Exchange connected, so most Exchange data, including [[Security Scenarios]]' Exchange checks, shows "not assessed".
- A comment on `TenantCredentials` says "Exchange admin APIs don't accept the client-secret flow". That's consistent with Microsoft's docs: app-only Exchange access needs a **certificate** and an **Entra role on the app**, not just a secret.

### What depends on it (inventory, 2026-09-30)
| Module / feature | Reads | Writes |
|---|---|---|
| [[Defender for Office 365 & TABL]] | Get-HostedContentFilterPolicy, Get-HostedOutboundSpamFilterPolicy, Get-AntiPhishPolicy, Get-MalwareFilterPolicy, Get-SafeLinksPolicy, Get-SafeAttachmentPolicy, Get-TenantAllowBlockListItems | New-/Remove-TenantAllowBlockListItems, MDO remediation |
| [[Exchange Mailbox Permissions]] | Get-Mailbox, Get-MailboxStatistics, Get-MailboxPermission, Get-RecipientPermission | Remove-MailboxPermission, Remove-RecipientPermission |
| [[Email Forwarding Rules Audit]] | Get-Mailbox, Get-InboxRule, Get-TransportRule | Disable-InboxRule, Set-Mailbox (clear forwarding), Disable-TransportRule |
| [[Mailflow Rules & Transport Hygiene]] | Get-TransportRule, Get-InboundConnector, Get-OutboundConnector, Get-RemoteDomain, Get-ExternalInOutlook, Get-OrganizationConfig | mailflow fixes |
| [[Domain Authentication]] | Get-AcceptedDomain, Get-DkimSigningConfig | none |
| [[Security Scenarios]] / sync | Get-AdminAuditLogConfig, Get-TransportConfig, Get-CASMailbox, Get-OrganizationConfig | Set-OrganizationConfig (mailbox auditing) |

UI gates: `!!tenant.credentials.exoRefreshToken` is checked separately in `PermissionsModal`, `DomainAuthModule`, `EmailForwardingModule`, `MailboxPermissionsModule`, `MailflowRulesModule`, `MdoPoliciesModule`, plus four sync gates in `graph-client.ts`: ten copies of the same "is Exchange connected" question (the duplicated-logic bug class in [[Optimization Plan]] item 7).

## Target: Microsoft's supported app-only model
From *App-only authentication in Exchange Online PowerShell* (Microsoft Learn, verified 2026-09-30):
1. **API permission:** Office 365 Exchange Online → **Exchange.ManageAsApp** (Application), admin-consented. For Security & Compliance (Purview) later: Microsoft Exchange Online Protection → Exchange.ManageAsApp.
2. **A role on the app's service principal** - the permission alone grants nothing:
   - **Global Reader**: read-only, covers every read above. Also reads the rest of the tenant, which is broader than Exchange.
   - **Exchange Administrator**: every Exchange read and write. High privilege.
   - ~~Custom Exchange role group (Microsoft's "Option 2")~~: narrowest, but setting it up needs an Exchange PowerShell session per tenant, so it's **excluded** by the no-sign-in requirement above.
   - Note: Microsoft says **Security Administrator lacks the anti-spam / anti-phishing permissions**, so it isn't enough for the MDO module.
3. **A certificate** (X.509, self-signed is fine). Microsoft documents app-only Exchange only with certificates. A client secret may obtain a token but isn't supported - don't build on it.

Consequences: no admin account, no device code, no refresh-token rotation (client-credentials tokens, simply re-requested), and the app's access is fixed by the assigned role, so read-only really is read-only.

## Phases

### Phase 0 : Spike on one tenant (verify before building)
A throwaway script against one test tenant (Crimson Line Live Demo) to confirm:
- A certificate-signed client-credentials token for `https://outlook.office365.com/.default` works against `adminapi/beta/{tenant}/InvokeCommand` for a read cmdlet (e.g. `Get-OrganizationConfig`), and which headers app-only needs (the PowerShell module sends an `X-AnchorMailbox` system-mailbox header in app-only mode - confirm whether the REST call needs it).
- The token's `roles` claim contains `Exchange.ManageAsApp` and its `wids` claim lists the assigned directory role template ids. That would let the permission check read the role straight from the token, like `decodeAppRolesFromToken` already does for Graph.
- The error shapes for "permission granted, no role assigned" and "role too weak for this cmdlet" (e.g. a write under Global Reader), so the UI can explain them.
- That **Global Reader** covers every read cmdlet above (TABL and the MDO policy cmdlets especially), and which write cmdlets fail under it.
- For the record only: whether a client secret works. Don't rely on it.
- Microsoft's "CNG certificates aren't supported" note is about the Windows certificate store the PowerShell module uses. Confirm a Node-generated RSA key signs a working assertion.

**Done when** the spike's findings are written into this note, and anything that contradicts the plan is changed here before Phase 1.

#### Phase 0 results (2026-09-30, Crimson Line Live Demo, read-only)
Setup: the user did the three portal steps (uploaded a 30-day spike certificate, added Exchange.ManageAsApp + consent, assigned Global Reader to the app). Script: `scratchpad/exo-spike/spike.js` (outside the repo; RS256 client assertion with `x5t` + `x5t#S256` headers from a Node/OpenSSL RSA key, so Microsoft's CNG note doesn't apply).
- **Certificate token issued, no sign-in.** Audience `https://outlook.office365.com`.
- **Token claims are enough to verify setup:** `roles` = `["Exchange.ManageAsApp"]`; `wids` contains Global Reader `f2ef992c-3afb-46b9-b7cf-a126ee74c451` plus `0997a1d0-0d1d-4acb-b408-d5ca73121e90`, which is **not** a directory role template (Graph returns 404 for it) - an ID Microsoft adds to app tokens. The permission check should match known role ids only.
- **No `X-AnchorMailbox` header needed:** the same `adminapi/beta/{tenant}/InvokeCommand` call works as-is with the app-only token.
- **22 of 22 read cmdlets work under Global Reader**: every cmdlet in the inventory above, including all six MDO policy reads, `Get-TenantAllowBlockListItems`, and per-mailbox `Get-MailboxPermission` / `Get-RecipientPermission` / `Get-MailboxStatistics` / `Get-InboxRule`. Latency 0.3-1.4 s per call, similar to delegated.
- **Values match the delegated sync:** UnifiedAuditLogIngestionEnabled = true, SmtpClientAuthenticationDisabled = true, as stored by the existing device-code connection.
- **Surprise - a client secret works too.** Once the app had Exchange.ManageAsApp and a role, a token from the tenant's *existing client secret* also ran `Get-OrganizationConfig` successfully. The old `TenantCredentials` comment ("Exchange admin APIs don't accept the client-secret flow") was wrong in practice; it most likely failed then because the app had neither the permission nor a role. **Microsoft still documents only certificates for this**, so the secret path is undocumented and could be blocked without notice.
- **The certificate also works for Graph** (a Graph token with the same 15 app roles as the secret), confirming the "Graph on the same certificate" follow-up is possible.
- Not tested (deliberately, read-only spike): write cmdlets and their error shapes under Global Reader. Do this in Phase 4, on a tenant where writes are wanted.

**Decision this raises (for the user):** use the **certificate** (Microsoft's documented path; needs the extra upload step and renewal) or the **existing client secret** (works today with just the permission and the role, zero extra setup, but undocumented). Recommended: build the certificate path as the supported default, and fall back automatically to the existing client secret when no certificate is uploaded, labelling that in the Permissions check as "working, not Microsoft-supported". If Microsoft ever blocks secrets here, the fallback degrades to "not assessed" rather than breaking anything.

### Phase 1 : Certificate credential
- `TenantCredentials` gains optional `exoAppCertificate?: { thumbprintSha1: string; thumbprintSha256: string; publicCertPem: string; encryptedPrivateKey: string; notBefore: string; notAfter: string; createdAt: string }` and `exoAuthMode?: "appOnly" | "delegated"`. The private key is encrypted with `CLARITY365_ENCRYPTION_KEY` like client secrets, is never shown or exported again, and is stripped by `sanitizeSnapshot`-style helpers everywhere a tenant leaves the server.
- **Certificate source** (decision 2): Clarity365 generates the key pair and a self-signed certificate per tenant and offers the public `.cer` for download to upload to the app registration. Alternatively, accept an uploaded PFX made with a provided PowerShell script.
- Pure, tested `buildClientAssertion(certificate, clientId, tenantId)`: an RS256 JWT with `x5t#S256` (and `x5t`) headers, as Entra expects for certificate credentials.
- Audit log entries for certificate create / replace / delete.

### Phase 2 : One Exchange auth path, two modes
- `getExoAccessToken` picks **app-only** when a certificate is configured, else **delegated** (today's device-code). The rest of `exo-client.ts` is unchanged, since `invokeExoCommand`'s interface stays the same. Token cache keyed by tenant + mode.
- One shared helper, `getExchangeAccess(tenant) → { available: boolean; mode: "appOnly" | "delegated" | "none"; canWrite: boolean; role?: string }`, **replaces all ten `!!exoRefreshToken` checks** (six UI modules, four sync gates). Tested.
- Tests with mocked fetch, like `exo-client.test.ts`: assertion built, correct scope, mode selection, fallback to delegated, no refresh-token rotation in app-only mode.

### Phase 3 : Permissions check and onboarding
- `PermissionsModal` gets an **Exchange Online access** section with three rows:
  - Exchange.ManageAsApp granted (from the token's `roles`).
  - Role assigned: Global Reader / Exchange Administrator (from `wids`, or a `roleManagement/directory/roleAssignments?$filter=principalId eq '{sp}'` lookup with the existing RoleManagement.Read.Directory).
  - Certificate valid, with its expiry date.
- Guided setup, **portal steps first**: generate certificate → download `.cer` → the three Entra portal steps above, each with a deep link and a screenshot-style description → "Test". An **optional** Microsoft Graph PowerShell script that does the same three steps is offered for people who prefer it, clearly labelled as needing a (one-time, setup-only) Graph sign-in. Device-code stays available as "Use delegated sign-in instead".
- Certificate-expiry warnings from 30 days out, in the modal, as a sync note, and as a [[CA Gap Analysis]]-style finding in [[Security Scenarios]]. The data behind Exchange checks disappears when the certificate lapses, so it mustn't expire silently.

### Phase 4 : Modules switch over
- The six modules read `getExchangeAccess(tenant)`. Empty states say what's missing ("Exchange app-only access: role not assigned") instead of always "Connect Exchange Online".
- **Writes** (decision 1) require `exoWriteEnabled` (kept as the explicit switch) **and** an access mode that can write: app-only with Exchange Administrator, or delegated. Under read-only app-only access, write buttons explain why they're unavailable instead of failing at Microsoft.
- Re-verify each module's data against a live app-only tenant (mailbox scan, TABL, DKIM, CAS, audit config).

### Phase 5 : Migration, docs, cleanup
- Existing device-code tenants keep working. A per-tenant "switch to app-only" in the Permissions check; once app-only is confirmed working, offer to clear the stored refresh token.
- Update the `TenantCredentials` comment, [[Core Graph Layer]], [[Security Infra]], [[Modals]], each affected module note, and the README's setup section.
- Bump `SNAPSHOT_SYNC_SCHEMA_VERSION` only if the snapshot shape changes (the credential shape isn't part of the snapshot).

### Later (separate decisions)
- **Graph on the same certificate** (the existing, unimplemented `authMode: "certificate"`), retiring client secrets, which Microsoft prefers. Low extra effort once Phase 1 exists.
- **Security & Compliance (Purview) app-only** for the DLP plans ([[DLP & Sensitivity Labels Plan]]): same certificate, the second Exchange.ManageAsApp permission, and a Compliance role.
- **GDAP + one multi-tenant app** (Microsoft's recommended MSP model) instead of an app registration per client. A bigger architectural change; worth its own plan if Clarity365 moves that way.

## Risks
- **Anyone holding the certificate has the app's role, with no user and no MFA.** With Exchange Administrator that equals an admin credential. Mitigations: read-only role by default, encrypted private key that's never exported, per-tenant certificates (one leak doesn't expose every client), expiry and rotation, and audit entries.
- Global Reader reads far more than Exchange. The narrower custom role group is excluded (it needs an Exchange PowerShell sign-in), so Global Reader is the least-privileged option that meets the no-sign-in requirement.
- The REST endpoint is `adminapi/beta` - the same one the delegated path already relies on, so no new stability risk, but Phase 0 must confirm app-only behaves the same.

## Decisions for review
1. **Exchange writes under app-only:** (a) read-only with **Global Reader** (default), keeping writes on the delegated sign-in fallback; (b) per tenant, assign **Exchange Administrator** instead to allow writes with no sign-in. (Custom role groups excluded, see the requirement.) **Recommended: (a) as the default, (b) as an explicit per-tenant choice.**
2. **Certificate source:** Clarity365 generates it (best experience; adds a small X.509 library dependency) or you upload a PFX made with a provided script. **Recommended: generate.**
3. **Graph on the same certificate** now or later? **Recommended: later**, as a follow-up once Exchange works.
4. **Keep device-code as a fallback?** **Recommended: yes**, for tenants where a role can't be assigned to the app, or to allow occasional writes on a read-only tenant. It's the only path that involves a sign-in, and it's never required.

Part of [[Clarity365 MOC]]. See also [[Security Simulations Plan]], [[Optimization Plan]].
