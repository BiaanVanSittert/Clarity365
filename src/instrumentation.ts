interface ShutdownGlobal {
  clarity365ShutdownHandlersRegistered?: boolean;
}

// Next.js calls register() once when the server process starts. Used here to kick
// off the auto-sync scheduler and register a graceful-shutdown handler - guarded
// to the Node.js runtime since better-sqlite3, the scheduler's setInterval, and
// process signal handlers have no business running in the Edge runtime.
//
// IMPORTANT: keep every dynamic import needed here directly inside this `if`
// block (not behind a separately-defined helper function called from it) -
// Next.js's instrumentation bundler strips nodejs-only code textually within
// this conditional for the Edge build; imports reached only indirectly (e.g.
// via a helper function invoked from here) are NOT stripped and break the
// Edge build by pulling in Node built-ins (fs, path, better-sqlite3's native
// binding) that don't resolve there.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startAutoSyncScheduler } = await import("./lib/services/scheduler");
    startAutoSyncScheduler();

    // Closes the SQLite connection on a graceful shutdown signal (interactive
    // Ctrl+C, or a container/orchestrator sending SIGTERM before SIGKILL) so
    // WAL contents get a clean checkpoint. Guarded via globalThis the same way
    // the scheduler is, so Next.js dev-mode hot-reloads don't stack duplicate
    // handlers. Note: this project's own `npm run stop`/`restart`
    // (scripts/stop.js) force-kills the process and bypasses these signals
    // entirely - this handler's main value is the interactive Ctrl+C path and
    // future non-Windows deployments.
    const g = globalThis as unknown as ShutdownGlobal;
    if (!g.clarity365ShutdownHandlersRegistered) {
      g.clarity365ShutdownHandlersRegistered = true;

      const shutdown = async (signal: string) => {
        try {
          const { tenantStore } = await import("./lib/services/tenant-store");
          tenantStore.close();
          console.log(`[Clarity365] Closed database connection on ${signal}.`);
        } catch (err) {
          console.error(`[Clarity365] Error closing database connection on ${signal}:`, err);
        } finally {
          process.exit(0);
        }
      };

      process.on("SIGINT", () => shutdown("SIGINT"));
      process.on("SIGTERM", () => shutdown("SIGTERM"));
    }
  }
}
