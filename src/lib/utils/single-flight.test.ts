import { describe, expect, it, vi } from "vitest";
import { singleFlight, singleFlightAfterCurrent } from "./single-flight";

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("singleFlight", () => {
  it("joins a run already in progress for the same key instead of starting another", async () => {
    const map = new Map<string, Promise<string>>();
    const d = deferred<string>();
    const start = vi.fn(() => d.promise);
    const a = singleFlight(map, "tenant-1", start);
    const b = singleFlight(map, "tenant-1", start);
    expect(start).toHaveBeenCalledTimes(1);
    d.resolve("synced");
    expect(await a).toBe("synced");
    expect(await b).toBe("synced");
    expect(map.size).toBe(0);
  });

  it("runs different keys independently and starts afresh once a run has finished", async () => {
    const map = new Map<string, Promise<number>>();
    let n = 0;
    const start = vi.fn(async () => ++n);
    await Promise.all([singleFlight(map, "a", start), singleFlight(map, "b", start)]);
    expect(start).toHaveBeenCalledTimes(2);
    await singleFlight(map, "a", start);
    expect(start).toHaveBeenCalledTimes(3);
  });

  it("clears the key when a run fails, so the next call can try again", async () => {
    const map = new Map<string, Promise<string>>();
    await expect(singleFlight(map, "a", () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
    expect(map.has("a")).toBe(false);
    expect(await singleFlight(map, "a", async () => "ok")).toBe("ok");
  });
});

describe("singleFlightAfterCurrent", () => {
  it("waits for the run in progress and then starts a new one", async () => {
    const map = new Map<string, Promise<string>>();
    const first = deferred<string>();
    const order: string[] = [];
    singleFlight(map, "t", () => first.promise.then((v) => (order.push(v), v)));
    const after = singleFlightAfterCurrent(map, "t", async () => (order.push("after-change"), "after-change"));
    first.resolve("before-change");
    expect(await after).toBe("after-change");
    expect(order).toEqual(["before-change", "after-change"]);
  });

  it("still runs when the earlier run failed", async () => {
    const map = new Map<string, Promise<string>>();
    const first = deferred<string>();
    singleFlight(map, "t", () => first.promise).catch(() => undefined);
    const after = singleFlightAfterCurrent(map, "t", async () => "fresh");
    first.reject(new Error("timed out"));
    expect(await after).toBe("fresh");
  });
});
