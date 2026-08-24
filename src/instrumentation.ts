// Next.js calls register() once when the server process starts. Used here to kick
// off the auto-sync scheduler — guarded to the Node.js runtime since better-sqlite3
// and the scheduler's setInterval have no business running in the Edge runtime.
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { startAutoSyncScheduler } = await import("./lib/services/scheduler");
    startAutoSyncScheduler();
  }
}
