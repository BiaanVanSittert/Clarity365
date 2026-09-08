---
tags: [ui]
---

# Modals

Eleven modal/drawer components under `src/components/modals/`. Linked from module notes by header anchor.

### AddTenantModal
Provision a new tenant (live Graph or simulation). → `POST /api/tenants`

### DeleteTenantModal
Remove a tenant. → `DELETE /api/tenants?id=`

### SettingsModal
System settings + password change. → `POST /api/auth/change-password`, `GET`/`POST /api/settings`

### PermissionsModal
Graph/EXO permission validation, device-code EXO connect flow. → `GET /api/tenants/{id}/permissions`, `GET .../exo-permissions`, `POST .../exo-connect/start`, `POST .../exo-connect/poll`, `PATCH /api/tenants/{id}`

### DeployCaPolicyModal
Deploy a single CA baseline policy live. → `POST /api/tenants/{id}/deploy-ca`. Used by [[Conditional Access Policy Scanner]].

### FleetBulkDeployModal
Bulk-deploy CA policies fleet-wide. → `POST /api/fleet/bulk-deploy`. Used by [[Fleet Baseline Rollout]].

### CompromisedAccountModal
Contain a compromised user (disable/revoke sessions). → `POST /api/tenants/{id}/incident-response/contain-user`. Used by [[Event Response (Incident Response)]].

### DeviceIsolationModal
Isolate/scan a device via Defender. → `POST .../isolate-device`, `POST .../scan-device`. Used by [[Event Response (Incident Response)]].

### ChangeConfirmationModal
Generic "review before you push a live change" confirmation — no fetch of its own, the caller performs the write after confirm. Reused by [[Fleet Baseline Drift]] and [[Fleet TABL Sync]].

### ReportPreviewModal
Print/PDF preview for Executive QBR reports. Used only by [[Executive Reporting (QBR)]].

### RemediationDrawer
Shows a generated remediation plan from [[Analysis & Generation]]'s `remediation-generator`.

Part of [[Clarity365 MOC]].
