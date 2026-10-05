---
tags: [ui]
---

# Modals

Twelve modal/drawer components under `src/components/modals/`. Linked from module notes by header anchor.

### AddTenantModal
Provision a new tenant (live Graph or simulation). → `POST /api/tenants`

Live-tenant setup is a deliberately short **3-step checklist** (client secret → API permissions incl. Office 365 Exchange Online `Exchange.ManageAsApp` → assign Exchange Administrator, or Global Reader for reports only), with the Graph permission list and the optional permissions folded into two collapsed sections. Keep it short: the user asked for no walls of caveats (2026-09-30). See [[Exchange App-Only Access Plan]].

### EditTenantCredentialsModal
Rotate/correct an existing live tenant's Entra app registration credentials (Directory ID, Application ID, Client Secret) - added after a live incident where a client's secret needed rotating and there was no UI for it anywhere (only `AddTenantModal` at creation time). → `PUT /api/tenants/{id}`, which already fully supported this (the `SECRET_MASK`/`keepExistingSecret` convention in `tenant-store.ts`'s `updateTenant()` predates this modal - it was built for `PermissionsModal`'s EXO connect flow) - this modal was purely the missing UI, no backend change needed. Opened from the tenant switcher dropdown in `Header.tsx` (a pencil icon next to the delete icon, live tenants only). Reset-on-open logic is deliberately keyed on `isOpen` alone, not the `tenant` prop - depending on `tenant` would re-fire on the `fetchTenants()` refresh a successful save triggers, wiping the success banner the instant it appeared (caught via live testing, not by inspection).

### DeleteTenantModal
Remove a tenant. → `DELETE /api/tenants?id=`

### SettingsModal
System settings + password change. → `POST /api/auth/change-password`, `GET`/`POST /api/settings`

### PermissionsModal
Graph/EXO permission validation. The Exchange section shows app-only access ("Connected - no sign-in needed" + the role and what it allows) or the same two setup steps, with the older device-code sign-in behind a small "use an admin sign-in instead" link. The write switch only appears when the access can write. → `GET /api/tenants/{id}/permissions`, `GET .../exo-permissions`, `POST .../exo-connect/start`, `POST .../exo-connect/poll`, `PATCH /api/tenants/{id}`

### DeployCaPolicyModal
Deploy a single CA baseline policy live. → `POST /api/tenants/{id}/deploy-ca`. Used by [[Conditional Access Policy Scanner]].

### FleetBulkDeployModal
Bulk-deploy CA policies fleet-wide. → `POST /api/fleet/bulk-deploy`. Used by [[Fleet Baseline Rollout]].

### CompromisedAccountModal
Contain a compromised user (disable/revoke sessions). → `POST /api/tenants/{id}/incident-response/contain-user`. Used by [[Event Response (Incident Response)]].

### DeviceIsolationModal
Isolate/scan a device via Defender. → `POST .../isolate-device`, `POST .../scan-device`. Used by [[Event Response (Incident Response)]].

### ChangeConfirmationModal
Generic "review before you push a live change" confirmation :  no fetch of its own, the caller performs the write after confirm. Reused by [[Fleet Baseline Drift]] and [[Fleet TABL Sync]].

### ReportPreviewModal
Print/PDF preview for Executive QBR reports. Used only by [[Executive Reporting (QBR)]].

### RemediationDrawer
Shows a generated remediation plan from [[Analysis & Generation]]'s `remediation-generator`.

### SignInReportModal (2026-10-01)
Sign-in report for one tenant: period and user filter, headline numbers, findings, "Open report (print or save as PDF)", "Download report" (HTML) and one CSV per table. All numbers come from [[Sign-in Report]]'s `buildSignInReport`. Has a server-render smoke test.

### Permission list (2026-10-01)
`AddTenantModal` no longer keeps its own permission arrays; it reads `REQUIRED_GRAPH_PERMISSION_NAMES` and `OPTIONAL_GRAPH_PERMISSIONS` from `src/lib/data/graph-permissions.ts`, the same list the Permissions check tests. `PermissionsModal` shows the client secret's expiry next to the auth mode.

Part of [[Clarity365 MOC]].

**Stacking (2026-10-05):** `common/Modal.tsx` keeps a stack of open modals, so one can open on top of another (a fix guide opened from [[Hardening Plan]]). Only the top modal answers Escape, and the page scroll lock is released when the last one closes.
