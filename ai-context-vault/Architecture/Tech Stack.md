---
tags: [architecture]
---

# Tech Stack

Links back to [[Clarity365 MOC]].

## Runtime
- **Next.js 14** (App Router), bound to `127.0.0.1` only :  never LAN/WAN exposed (see [[Security & Auth]])
- **React 18**, **TypeScript 5.5**
- **better-sqlite3 13** :  new as of the Sep 2026 codebase (`data/clarity365.db`): operator auth + encrypted tenant secrets. See [[Security & Auth]]
- **Vitest 4** :  `npm test` (`vitest run`). ~25 `*.test.ts` files, concentrated in `src/lib/services/`. See [[Testing]]

## UI
- **Radix UI** primitives (dialog, dropdown-menu, popover, select, tabs, tooltip) :  unstyled, accessible base for all modals/menus
- **Tailwind CSS 3** :  utility styling, Bloomberg-terminal-inspired high-density aesthetic
- **Recharts 2** :  score gauges, trend lines, compliance charts
- **lucide-react** :  icon set
- **clsx** + **tailwind-merge** :  conditional class composition

## Scripts (`package.json`)
| Script            | Purpose                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `dev`             | `next dev -H 127.0.0.1 -p 3000`                                                                                                          |
| `stop`            | `scripts/stop.js` :  frees ports 3000 and 8365 (graceful SIGTERM/taskkill, then force-kill after ~1.5s)                                   |
| `restart`         | stop + dev                                                                                                                               |
| `build` / `start` | production build/serve, still localhost-bound                                                                                            |
| `type-check`      | `tsc --noEmit`                                                                                                                           |
| `test`            | `vitest run`                                                                                                                             |
| `start:installer` | `scripts/installer.js` :  wizard that seeds demo tenants (Contoso E5, Northwind BP, Fabrikam E3, Woodgrove Zero-Trust) and launches `dev` |

## Deployment
- `Dockerfile` + `docker-compose.yml` :  single-command local deployment, still localhost-only by design
- No external database, no cloud dependency beyond the Microsoft Graph / Exchange Online APIs the operator's own app registrations call

## Notable absence
No dependency-injection framework, no ORM (raw `better-sqlite3` statements presumably in `auth.ts`/store code :  verify), no state-management library (React state + [[Tenant Store]] singleton instead). Small, deliberately un-fancy stack for a tool that has to be auditable by security teams.
