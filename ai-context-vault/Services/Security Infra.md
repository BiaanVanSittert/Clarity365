---
tags: [service, security]
---

# Security Infra

Five files. See [[Security & Auth]] for the end-to-end login flow these compose into.

- **auth.ts** :  Web Crypto only (Edge-safe, no Node `crypto`). `createSessionToken`/`verifySessionToken`, HMAC-SHA256, 12h TTL, `timingSafeEqualStr`. No local imports. **No test file** :  this is the entire login gate's session security, untested. See [[Testing]].
- **crypto.ts** :  Node `crypto` only. `encryptSecret`/`decryptSecret` (AES-256-GCM, for tenant client secrets at rest) and `hashPassword`/`verifyPasswordHash` (scrypt, for the operator password :  deliberately slow/memory-hard, distinct from the fast HMAC in `auth.ts`). Has a test. Used by [[Tenant Store]].
- **rate-limit.ts** :  `isRateLimited`. In-memory only, no imports. Explicitly documented as **not multi-instance-safe**. No test. Applied per-route by string key (`"auth-login"`, `"auth-setup"`, `"auth-change-password"`) rather than centrally in middleware.
- **scheduler.ts** :  `startAutoSyncScheduler` (setInterval-based auto-sync loop). Imports [[Tenant Store]]. No test.
- **domain-dns-checker.ts** :  see [[Data Mappers]] (grouped there since it's a mapper by function, but it's the only service hitting public DNS instead of Graph/EXO).

Part of [[Clarity365 MOC]].
