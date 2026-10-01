import { beforeEach, describe, expect, it, vi } from "vitest";
import { getSyncAllStatus, requestStopSyncAll, resetSyncAllForTests, startSyncAll, SyncAllDeps } from "./sync-all";

const TENANTS = [
  { id: "t1", displayName: "Alpha" },
  { id: "t2", displayName: "Bravo" },
  { id: "t3", displayName: "Charlie" },
];

// A sync that only finishes when the test says so, to observe the pass mid-flight.
function controlledDeps() {
  const release: Record<string, (r: { outcome: string; error?: string }) => void> = {};
  const started: string[] = [];
  const deps: SyncAllDeps = {
    listTenants: () => TENANTS,
    syncTenant: (id) =>
      new Promise((resolve) => {
        started.push(id);
        release[id] = resolve;
      }),
  };
  return { deps, release, started };
}
const tick = () => new Promise((r) => setTimeout(r, 0));

describe("startSyncAll", () => {
  beforeEach(() => resetSyncAllForTests());

  it("syncs every tenant, strictly one at a time, in order", async () => {
    const { deps, release, started } = controlledDeps();
    const run = startSyncAll(deps, "manual");
    expect(run.started).toBe(true);
    await tick();
    // Only the first tenant has started; the others wait.
    expect(started).toEqual(["t1"]);
    expect(getSyncAllStatus()).toMatchObject({ running: true, total: 3, completed: 0, current: { tenantId: "t1", tenantName: "Alpha" } });

    release.t1({ outcome: "synced" });
    await tick();
    expect(started).toEqual(["t1", "t2"]);
    expect(getSyncAllStatus()).toMatchObject({ completed: 1, current: { tenantName: "Bravo" } });

    release.t2({ outcome: "synced" });
    await tick();
    release.t3({ outcome: "synced" });
    await run.done;
    const status = getSyncAllStatus();
    expect(status).toMatchObject({ running: false, completed: 3, stopped: false, current: undefined });
    expect(status.results.map((r) => [r.tenantName, r.outcome])).toEqual([
      ["Alpha", "synced"],
      ["Bravo", "synced"],
      ["Charlie", "synced"],
    ]);
    expect(status.finishedAt).toBeTruthy();
  });

  it("keeps going when one tenant fails or throws, and records why", async () => {
    const onTenantError = vi.fn();
    const run = startSyncAll(
      {
        listTenants: () => TENANTS,
        syncTenant: async (id) => {
          if (id === "t1") return { outcome: "stale_fallback", error: "Bad credentials" };
          if (id === "t2") throw new Error("database is locked");
          return { outcome: "synced" };
        },
        onTenantError,
      },
      "scheduled"
    );
    await run.done;
    expect(getSyncAllStatus().results.map((r) => [r.outcome, r.error])).toEqual([
      ["failed", "Bad credentials"],
      ["failed", "database is locked"],
      ["synced", undefined],
    ]);
    expect(onTenantError).toHaveBeenCalledTimes(1);
    expect(onTenantError.mock.calls[0][0]).toEqual(TENANTS[1]);
  });

  it("refuses to start a second pass while one is running", async () => {
    const { deps, release } = controlledDeps();
    const first = startSyncAll(deps, "scheduled");
    await tick();
    const second = startSyncAll(deps, "manual");
    expect(second.started).toBe(false);
    expect(second.status.source).toBe("scheduled");
    release.t1({ outcome: "synced" });
    await tick();
    release.t2({ outcome: "synced" });
    await tick();
    release.t3({ outcome: "synced" });
    await first.done;
    // Once finished, a new pass can start.
    expect(startSyncAll({ listTenants: () => [], syncTenant: async () => undefined }, "manual").started).toBe(true);
  });

  it("stops after the tenant in progress when asked", async () => {
    const { deps, release, started } = controlledDeps();
    const run = startSyncAll(deps, "manual");
    await tick();
    expect(requestStopSyncAll().stopRequested).toBe(true);
    // The tenant already syncing is allowed to finish.
    expect(getSyncAllStatus().running).toBe(true);
    release.t1({ outcome: "synced" });
    await run.done;
    expect(started).toEqual(["t1"]);
    expect(getSyncAllStatus()).toMatchObject({ running: false, stopped: true, completed: 1, total: 3 });
  });

  it("finishes immediately when there are no live tenants", async () => {
    const run = startSyncAll({ listTenants: () => [], syncTenant: async () => undefined }, "manual");
    await run.done;
    expect(getSyncAllStatus()).toMatchObject({ running: false, total: 0, completed: 0, stopped: false });
  });

  it("ignores a stop request when nothing is running", () => {
    expect(requestStopSyncAll()).toMatchObject({ running: false, stopRequested: false });
  });
});
