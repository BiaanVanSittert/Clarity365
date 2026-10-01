// "Sync all tenants": one pass over every live tenant, strictly one at a
// time, with a status the UI can poll. The background auto-sync
// (scheduler.ts) and the fleet overview's "Sync all tenants" button both run
// through here, so there is never more than one pass at once.
//
// A sync only READS from Microsoft 365 - it changes nothing in any tenant.
// That is why this one fleet-wide action exists despite the project rule
// that every action is scoped to a single tenant (explicitly approved by the
// user, 2026-10-01). Do not extend this into anything that writes.
//
// No tenant-store import: the tenant list and the per-tenant sync are passed
// in, which keeps this unit-testable without a database.

export type SyncAllSource = "manual" | "scheduled";

export interface SyncAllTenantRef {
  id: string;
  displayName: string;
}

export interface SyncAllResult {
  tenantId: string;
  tenantName: string;
  outcome: "synced" | "failed";
  error?: string;
  finishedAt: string;
}

export interface SyncAllStatus {
  running: boolean;
  source?: SyncAllSource;
  startedAt?: string;
  finishedAt?: string;
  total: number;
  completed: number;
  current?: { tenantId: string; tenantName: string };
  // Asked to stop: the tenant in progress finishes, the rest are skipped.
  stopRequested: boolean;
  // True when the last pass ended early because of a stop request.
  stopped: boolean;
  results: SyncAllResult[];
}

export interface SyncAllDeps {
  listTenants: () => SyncAllTenantRef[];
  syncTenant: (tenantId: string, source: SyncAllSource) => Promise<{ outcome: string; error?: string } | undefined>;
  // Called when syncTenant throws outright rather than returning a result.
  onTenantError?: (tenant: SyncAllTenantRef, error: unknown) => void;
  now?: () => Date;
}

interface SyncAllGlobal {
  clarity365SyncAll?: SyncAllStatus;
}

// globalThis for the same reason as the scheduler: a dev-mode hot reload
// must not lose track of a pass that is still running.
const g = globalThis as unknown as SyncAllGlobal;
const idle = (): SyncAllStatus => ({ running: false, total: 0, completed: 0, stopRequested: false, stopped: false, results: [] });

export function getSyncAllStatus(): SyncAllStatus {
  if (!g.clarity365SyncAll) g.clarity365SyncAll = idle();
  return g.clarity365SyncAll;
}

// Starts a pass unless one is already running. Returns immediately; `done`
// resolves when the pass ends (the scheduler awaits it, the API route doesn't).
export function startSyncAll(deps: SyncAllDeps, source: SyncAllSource): { started: boolean; status: SyncAllStatus; done: Promise<void> } {
  const existing = getSyncAllStatus();
  if (existing.running) return { started: false, status: existing, done: Promise.resolve() };

  const now = deps.now || (() => new Date());
  const tenants = deps.listTenants();
  const status: SyncAllStatus = { running: true, source, startedAt: now().toISOString(), total: tenants.length, completed: 0, stopRequested: false, stopped: false, results: [] };
  g.clarity365SyncAll = status;

  const done = (async () => {
    for (const tenant of tenants) {
      if (status.stopRequested) {
        status.stopped = true;
        break;
      }
      status.current = { tenantId: tenant.id, tenantName: tenant.displayName };
      let outcome: SyncAllResult["outcome"] = "failed";
      let error: string | undefined;
      try {
        const result = await deps.syncTenant(tenant.id, source);
        if (result?.outcome === "synced") outcome = "synced";
        else error = result?.error || "Sync failed.";
      } catch (err) {
        error = err instanceof Error ? err.message : String(err);
        deps.onTenantError?.(tenant, err);
      }
      status.results.push({ tenantId: tenant.id, tenantName: tenant.displayName, outcome, error, finishedAt: now().toISOString() });
      status.completed++;
    }
    status.current = undefined;
    status.running = false;
    status.finishedAt = now().toISOString();
  })();

  return { started: true, status, done };
}

// The tenant being synced can't be interrupted; this stops the pass after it.
export function requestStopSyncAll(): SyncAllStatus {
  const status = getSyncAllStatus();
  if (status.running) status.stopRequested = true;
  return status;
}

export function resetSyncAllForTests(): void {
  g.clarity365SyncAll = idle();
}
