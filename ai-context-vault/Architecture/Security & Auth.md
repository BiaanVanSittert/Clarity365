---
tags: [architecture, security]
---

# Security & Auth

Added wholesale in the 203-commit gap between the outer checkout and `origin/main` (see [[Clarity365 MOC#A note on repo history|repo history note]]). Single-operator gate :  not multi-user.

## Flow
1. **middleware.ts** (Edge runtime) :  matcher excludes `/login`, `/api/auth/{login,setup,status}`, static assets. Reads the `clarity365_session` cookie, calls `verifySessionToken`. Valid → pass through. Invalid + `/api/*` → 401 JSON. Invalid + page → redirect to `/login?from=<path>`.
2. **auth.ts** ([[Security Infra]]) :  Web Crypto (Edge-safe), HMAC-SHA256-signs `{iat, exp}` using `CLARITY365_SESSION_SECRET`, 12h TTL, stateless (no DB lookup per request). **Untested.**
3. **crypto.ts** ([[Security Infra]]) :  Node-only, two concerns in one file: AES-256-GCM encrypt/decrypt for tenant Graph client secrets at rest (`CLARITY365_ENCRYPTION_KEY`, format `enc:v1:iv:tag:ciphertext`), and scrypt password hashing for the operator login (`scrypt:v1:salt:hash`) :  deliberately slow/memory-hard, distinct from the fast HMAC used for sessions.
4. **instrumentation.ts** :  Next.js `register()` hook, Node-runtime-only (Edge build strips it). Starts `scheduler.startAutoSyncScheduler()` and registers `SIGINT`/`SIGTERM` to close the SQLite connection cleanly. Documented gotcha: dynamic imports must stay inline inside the runtime-check `if` block, or Next's Edge bundler fails trying to strip the native `better-sqlite3` binding.
5. **Login flow**: `/api/auth/status` (public :  tells the login page whether to show "create password" or normal login) → `/api/auth/setup` (first run only, refuses if a password already exists) → `/api/auth/login` (rate-limited 10/15min, sets httpOnly/sameSite=lax cookie) → `/api/auth/logout` (zeroes the cookie). `change-password` requires an existing valid session and rate-limits separately.

## Operational requirement
`.env.local` (gitignored, not present by default) must define `CLARITY365_SESSION_SECRET` and `CLARITY365_ENCRYPTION_KEY` before first run. As of `scripts/ensure-env.js`, this is no longer a manual step :  it runs as a `predev`/`prebuild`/`prestart` hook (and is inlined into `restart`, which calls `next dev` directly and so bypasses `predev`) and writes both as random 32-byte hex values into `.env.local` if either is blank, without touching a value that's already set there or in a real environment variable. Previously, a fresh clone with no `.env.local` would let first-run password setup save the password hash (`tenantStore.setPasswordHash`, which needs nothing but `crypto.hashPassword`) and only then fail in `auth.createSessionToken` with "CLARITY365_SESSION_SECRET is not set" :  leaving the operator with a configured password but no way to get a session, on every subsequent attempt including login. See [[Optimization Plan]]. **Changing `CLARITY365_ENCRYPTION_KEY` after tenants exist makes their stored secrets unreadable** :  there's no re-encryption path.

## Known gaps
- `auth.ts` (session verification) has **no test** :  see [[Testing]]
- `rate-limit.ts` is in-memory only, **not multi-instance-safe** :  fine for the single-process localhost design today, would silently stop working under any horizontal scaling
- Rate limiting is applied per-route by string key, not centrally in middleware :  a new auth route can forget to call it

Part of [[Clarity365 MOC]].
