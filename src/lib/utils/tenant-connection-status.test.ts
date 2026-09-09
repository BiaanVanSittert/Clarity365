import { describe, it, expect } from "vitest";
import { getConnectionStatusDisplay } from "./tenant-connection-status";

describe("tenant-connection-status", () => {
  it("maps healthy to a pass pill, with context-specific copy", () => {
    expect(getConnectionStatusDisplay("healthy", "fleet")).toEqual({ pillStatus: "pass", label: "Healthy" });
    expect(getConnectionStatusDisplay("healthy", "header")).toEqual({ pillStatus: "pass", label: "Sync Healthy" });
  });

  it("maps degraded to a warn pill identically in both contexts", () => {
    expect(getConnectionStatusDisplay("degraded", "fleet")).toEqual({ pillStatus: "warn", label: "Degraded" });
    expect(getConnectionStatusDisplay("degraded", "header")).toEqual({ pillStatus: "warn", label: "Degraded" });
  });

  it("maps error to a fail pill identically in both contexts", () => {
    expect(getConnectionStatusDisplay("error", "fleet")).toEqual({ pillStatus: "fail", label: "Error" });
    expect(getConnectionStatusDisplay("error", "header")).toEqual({ pillStatus: "fail", label: "Error" });
  });

  it("maps disconnected to a fail pill distinct from error, identically in both contexts", () => {
    expect(getConnectionStatusDisplay("disconnected", "fleet")).toEqual({ pillStatus: "fail", label: "Not Connected" });
    expect(getConnectionStatusDisplay("disconnected", "header")).toEqual({ pillStatus: "fail", label: "Not Connected" });
  });

  it("defaults to fleet context when none is given", () => {
    expect(getConnectionStatusDisplay("healthy")).toEqual({ pillStatus: "pass", label: "Healthy" });
  });
});
