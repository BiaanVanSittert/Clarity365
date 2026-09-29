import { describe, expect, it } from "vitest";
import { SNAPSHOT_SYNC_SCHEMA_VERSION, shouldRefuseSnapshotOverwrite, storedSchemaVersion } from "./sync-schema-version";

describe("sync schema version guard", () => {
  it("treats a snapshot without a stamp as version 0", () => {
    expect(storedSchemaVersion(undefined)).toBe(0);
    expect(storedSchemaVersion({})).toBe(0);
    expect(storedSchemaVersion({ syncSchemaVersion: 2 })).toBe(2);
  });

  it("refuses only when the stored snapshot is from a newer build", () => {
    expect(shouldRefuseSnapshotOverwrite(0)).toBe(false);
    expect(shouldRefuseSnapshotOverwrite(SNAPSHOT_SYNC_SCHEMA_VERSION)).toBe(false);
    expect(shouldRefuseSnapshotOverwrite(SNAPSHOT_SYNC_SCHEMA_VERSION + 1)).toBe(true);
    // The 2026-09-29 incident, replayed with the guard in place: a stale build
    // (version 2) meeting data from a future build (version 3).
    expect(shouldRefuseSnapshotOverwrite(3, 2)).toBe(true);
  });
});
