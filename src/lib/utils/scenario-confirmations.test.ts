import { describe, expect, it } from "vitest";
import { getConfirmationState, isScenarioConfirmationKey } from "./scenario-confirmations";

const NOW = new Date("2026-10-02T12:00:00Z");

describe("getConfirmationState", () => {
  it("is valid for a year from the day it was given", () => {
    expect(getConfirmationState({ status: "inPlace", confirmedAt: "2026-01-15T09:00:00Z", note: "checked with client" }, NOW)).toEqual({
      status: "inPlace",
      confirmedAt: "2026-01-15T09:00:00Z",
      note: "checked with client",
      expired: false,
      expiresAt: "2027-01-15T09:00:00.000Z",
    });
  });

  it("lapses exactly at 365 days", () => {
    expect(getConfirmationState({ status: "inPlace", confirmedAt: "2025-10-02T12:00:01Z" }, NOW)?.expired).toBe(false);
    expect(getConfirmationState({ status: "inPlace", confirmedAt: "2025-10-02T12:00:00Z" }, NOW)?.expired).toBe(true);
  });

  it("ignores a missing or unreadable confirmation", () => {
    expect(getConfirmationState(undefined, NOW)).toBeUndefined();
    expect(getConfirmationState({ status: "inPlace", confirmedAt: "not a date" }, NOW)).toBeUndefined();
  });
});

describe("isScenarioConfirmationKey", () => {
  it("accepts only the known checks", () => {
    expect(isScenarioConfirmationKey("alert-audit-config")).toBe(true);
    expect(isScenarioConfirmationKey("sharepoint-default-link")).toBe(true);
    expect(isScenarioConfirmationKey("anything-else")).toBe(false);
    expect(isScenarioConfirmationKey(undefined)).toBe(false);
  });
});
