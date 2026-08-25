import { tenantStore } from "./tenant-store";

// Background auto-sync, driven by Settings > Auto-Sync Interval (Minutes). A plain
// setInterval checker rather than a cron dependency — the setting is just "every N
// minutes", not a cron expression, so a periodic check-and-run is all that's needed.
//
// Guarded via globalThis the same way tenantStore's singleton is, so Next.js dev-mode
// hot-reloads don't spawn duplicate timers. Skipped entirely during `next build`,
// which briefly instantiates this module for static generation but should never fire
// background network calls.

const CHECK_INTERVAL_MS = 60_000;

interface SchedulerGlobal {
  clarity365SchedulerStarted?: boolean;
  clarity365LastAutoSyncAt?: number;
}

const g = globalThis as unknown as SchedulerGlobal;

export function startAutoSyncScheduler() {
  if (process.env.NEXT_PHASE === "phase-production-build") return;
  if (g.clarity365SchedulerStarted) return;
  g.clarity365SchedulerStarted = true;
  // Start the clock now, not at epoch — avoids an immediate sync-all on every server
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

    const liveTenants = tenantStore.getAllTenants().filter((t) => t.credentials.authMode !== "mock");
    for (const tenant of liveTenants) {
      try {
        const result = await tenantStore.syncTenant(tenant.id, "scheduled");
        if (result?.outcome === "synced") {
          console.log(`[Clarity365 Scheduler] Auto-synced '${tenant.displayName}'.`);
        } else {
          // syncTenant already wrote a "tenant_sync_failure" audit log entry for
          // stale_fallback/no_data outcomes — just surface it to the console here.
          console.error(`[Clarity365 Scheduler] Auto-sync failed for '${tenant.displayName}': ${result?.error}`);
        }
      } catch (err) {
        // syncTenant threw outright (e.g. a DB error) rather than returning a
        // result — log it here since there was no return value to log from.
        console.error(`[Clarity365 Scheduler] Auto-sync failed for '${tenant.displayName}':`, err);
        tenantStore.addAuditLogEntry({
          timestamp: new Date().toISOString(),
          category: "tenant_sync_failure",
          action: "Scheduled sync failed",
          tenantId: tenant.id,
          tenantName: tenant.displayName,
          success: false,
          detail: `Unexpected exception: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  }, CHECK_INTERVAL_MS);

  console.log("[Clarity365 Scheduler] Auto-sync scheduler started (checks every 60s).");
}
