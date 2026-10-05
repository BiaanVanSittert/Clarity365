// The shape version of a live-synced TenantSecuritySnapshot. Bump this
// whenever fetchLiveTenantSnapshot() starts storing data an older build
// would drop (new fields, a mapper that keeps more of a Graph response).
//
// Why it exists: on 2026-09-29 a dev server started before Security
// Simulations Stage 1 kept running its background scheduler, which re-synced
// tenants every 30 minutes with the old mapper and silently overwrote
// snapshots a newer build had just written (see ai-context-vault/Services/
// Tenant Store.md). With this stamp, a build refuses to overwrite a snapshot
// written by a newer build. It only protects builds from version 2 onward;
// anything older than this file can't know to check.
//
// History:
//   (absent) - before this stamp existed
//   2        - Security Simulations Stages 1-2: extended CA policy fields,
//              named locations, identity settings, role template ids
//   3        - Security Simulations Stage 5: SharePoint security settings,
//              Exchange audit/protocol settings, PIM role assignments,
//              OAuth consent grants
//   4        - sign-in coverage and authentication details (beta sign-in
//              log), missing-permission list on sync health
//   5        - alert policies (Security & Compliance PowerShell)
export const SNAPSHOT_SYNC_SCHEMA_VERSION = 5;

export function storedSchemaVersion(snapshot: { syncSchemaVersion?: number } | undefined): number {
  return typeof snapshot?.syncSchemaVersion === "number" ? snapshot.syncSchemaVersion : 0;
}

// True when the stored snapshot came from a newer build than the one now
// trying to save - the save must be refused, or newer data is lost.
export function shouldRefuseSnapshotOverwrite(storedVersion: number, runningVersion: number = SNAPSHOT_SYNC_SCHEMA_VERSION): boolean {
  return storedVersion > runningVersion;
}
