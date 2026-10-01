import { tenantStore } from "./tenant-store";
import { startSyncAll, SyncAllDeps, SyncAllStatus } from "./sync-all";

// Background auto-sync, driven by Settings > Auto-Sync Interval (Minutes). A plain
// setInterval checker rather than a cron dependency - the setting is just "every N
// minutes", not a cron expression, so a periodic check-and-run is all that's needed.
//
// Guarded via globalThis the same way tenantStore's singleton is, so Next.js dev-mode
// hot-reloads don't spawn duplicate timers. Skipped entirely during `next build`,
// which briefly instantiates this module for static generation but should never fire
// background network calls.
//
// The pass itself (every live tenant, one at a time) lives in sync-all.ts and is
// shared with the fleet overview's "Sync all tenants" button, so the two can never
// run at the same time.

const CHECK_INTERVAL_MS = 60_000;

interface SchedulerGlobal {
  clarity365SchedulerStarted?: boolean;
  clarity365LastAutoSyncAt?: number;
}

const g = globalThis as unknown as SchedulerGlobal;

function tenantStoreSyncDeps(): SyncAllDeps {
  return {
    listTenants: () =>
      tenantStore
        .getAllTenants()
        .filter((t) => t.credentials.authMode !== "mock")
        .map((t) => ({ id: t.id, displayName: t.displayName })),
    syncTenant: async (tenantId, source) => {
      const result = await tenantStore.syncTenant(tenantId, source);
      const name = tenantStore.getTenant(tenantId)?.displayName || tenantId;
      const label = source === "scheduled" ? "Auto-sync" : "Sync all";
      if (result?.outcome === "synced") {
        console.log(`[Clarity365 Scheduler] ${label}: synced '${name}'.`);
      } else {
        // syncTenant already wrote a "tenant_sync_failure" audit log entry for
        // stale_fallback/no_data outcomes - just surface it to the console here.
        console.error(`[Clarity365 Scheduler] ${label} failed for '${name}': ${result?.error}`);
      }
      return result;
    },
    // syncTenant threw outright (e.g. a DB error) rather than returning a
    // result - log it here since there was no return value to log from.
    onTenantError: (tenant, err) => {
      console.error(`[Clarity365 Scheduler] Sync failed for '${tenant.displayName}':`, err);
      tenantStore.addAuditLogEntry({
        timestamp: new Date().toISOString(),
        category: "tenant_sync_failure",
        action: "Sync failed",
        tenantId: tenant.id,
        tenantName: tenant.displayName,
        success: false,
        detail: `Unexpected exception: ${err instanceof Error ? err.message : String(err)}`,
      });
    },
  };
}

// The "Sync all tenants" button. Read-only towards the tenants: it only
// refreshes Clarity365's copy of each tenant's data. Also resets the
// auto-sync clock, so a scheduled pass doesn't repeat the work straight after.
export function startManualSyncAll(): { started: boolean; status: SyncAllStatus } {
  const run = startSyncAll(tenantStoreSyncDeps(), "manual");
  if (run.started) {
    g.clarity365LastAutoSyncAt = Date.now();
    run.done.then(() => {
      g.clarity365LastAutoSyncAt = Date.now();
    });
  }
  return { started: run.started, status: run.status };
}

export function startAutoSyncScheduler() {
  if (process.env.NEXT_PHASE === "phase-production-build") return;
  if (g.clarity365SchedulerStarted) return;
  g.clarity365SchedulerStarted = true;
  // Start the clock now, not at epoch - avoids an immediate sync-all on every server
  // boot (including frequent dev-server restarts), which would otherwise fire within
  // the first check cycle.
  g.clarity365LastAutoSyncAt = Date.now();

  setInterval(async () => {
    const settings = tenantStore.getSettings();
    const intervalMs = settings.autoSyncIntervalMinutes * 60_000;
    if (!intervalMs || intervalMs <= 0) return;

    const now = Date.now();
    if (now - (g.clarity365LastAutoSyncAt ?? 0) < intervalMs) return;
    g.clarity365LastAutoSyncAt = now;

    // Does nothing if a pass (manual or an earlier scheduled one) is still running.
    await startSyncAll(tenantStoreSyncDeps(), "scheduled").done;
  }, CHECK_INTERVAL_MS);

  console.log("[Clarity365 Scheduler] Auto-sync scheduler started (checks every 60s).");
}
