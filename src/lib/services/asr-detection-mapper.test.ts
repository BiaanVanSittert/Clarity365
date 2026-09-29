import { describe, it, expect } from "vitest";
import { mapActionTypeToRule, buildActivitySummaries, synthesizeMockActivity } from "./asr-detection-mapper";
import { ASR_RULE_DEFINITIONS } from "../data/asr-rule-definitions";

const RANSOMWARE_ID = "c1db55ab-c21a-4637-bb3f-a12568109d35";
const SAFE_MODE_ID = "33ddedf1-c6e0-47cb-833e-de6133960387"; // has a WarnBypassed action type
const WEBSHELL_ID = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"; // no telemetry at all

describe("mapActionTypeToRule", () => {
  it("resolves a real Audited action type to its rule and the audit bucket", () => {
    expect(mapActionTypeToRule("AsrRansomwareAudited")).toEqual({ ruleId: RANSOMWARE_ID, kind: "audit" });
  });

  it("resolves a real Blocked action type to its rule and the block bucket", () => {
    expect(mapActionTypeToRule("AsrRansomwareBlocked")).toEqual({ ruleId: RANSOMWARE_ID, kind: "block" });
  });

  it("resolves a WarnBypassed action type to the warn_bypassed bucket", () => {
    expect(mapActionTypeToRule("AsrSafeModeRebootWarnBypassed")).toEqual({ ruleId: SAFE_MODE_ID, kind: "warn_bypassed" });
  });

  it("returns null for an unknown action type", () => {
    expect(mapActionTypeToRule("SomeUnrelatedActionType")).toBeNull();
  });
});

describe("buildActivitySummaries", () => {
  it("zero-fills every rule with no hits, and returns exactly 19 entries", () => {
    const summaries = buildActivitySummaries({});
    expect(summaries.length).toBe(ASR_RULE_DEFINITIONS.length);
    expect(summaries.every((s) => s.auditHitCount === 0 && s.blockHitCount === 0 && s.warnBypassedCount === 0)).toBe(true);
  });

  it("aggregates counts onto the correct rule and bucket", () => {
    const summaries = buildActivitySummaries({ AsrRansomwareAudited: 5, AsrRansomwareBlocked: 2 });
    const ransomware = summaries.find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(ransomware.auditHitCount).toBe(5);
    expect(ransomware.blockHitCount).toBe(2);
  });

  it("ignores unknown action types instead of throwing", () => {
    expect(() => buildActivitySummaries({ NotARealActionType: 3 })).not.toThrow();
  });
});

describe("synthesizeMockActivity", () => {
  it("always synthesizes zero activity for a Not Configured rule", () => {
    const summaries = synthesizeMockActivity([{ ruleId: RANSOMWARE_ID, mode: "not_configured" }], "seed-1");
    const ransomware = summaries.find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(ransomware).toEqual({ ruleId: RANSOMWARE_ID, auditHitCount: 0, blockHitCount: 0, warnBypassedCount: 0 });
  });

  it("always synthesizes zero activity for the no-telemetry Webshell rule regardless of mode", () => {
    const summaries = synthesizeMockActivity([{ ruleId: WEBSHELL_ID, mode: "block" }], "seed-1");
    const webshell = summaries.find((s) => s.ruleId === WEBSHELL_ID)!;
    expect(webshell).toEqual({ ruleId: WEBSHELL_ID, auditHitCount: 0, blockHitCount: 0, warnBypassedCount: 0 });
  });

  it("is deterministic - the same seed and rule states produce the same numbers every time", () => {
    const ruleStates = [{ ruleId: RANSOMWARE_ID, mode: "audit" as const }];
    const first = synthesizeMockActivity(ruleStates, "tenant-a");
    const second = synthesizeMockActivity(ruleStates, "tenant-a");
    expect(first).toEqual(second);
  });

  it("defaults to not_configured for a rule missing from the input, synthesizing zero", () => {
    const summaries = synthesizeMockActivity([], "seed-1");
    expect(summaries.every((s) => s.auditHitCount === 0 && s.blockHitCount === 0)).toBe(true);
  });

  it("scales activity counts by the selected time range - 7d < 30d < all", () => {
    const ruleStates = [{ ruleId: RANSOMWARE_ID, mode: "audit" as const }];
    const sevenDay = synthesizeMockActivity(ruleStates, "tenant-scale", "7d").find((s) => s.ruleId === RANSOMWARE_ID)!;
    const thirtyDay = synthesizeMockActivity(ruleStates, "tenant-scale", "30d").find((s) => s.ruleId === RANSOMWARE_ID)!;
    const allTime = synthesizeMockActivity(ruleStates, "tenant-scale", "all").find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(sevenDay.auditHitCount).toBeLessThanOrEqual(thirtyDay.auditHitCount);
    expect(thirtyDay.auditHitCount).toBeLessThanOrEqual(allTime.auditHitCount);
  });

  it("defaults to the 30-day scale when no time range is given", () => {
    const ruleStates = [{ ruleId: RANSOMWARE_ID, mode: "audit" as const }];
    const defaulted = synthesizeMockActivity(ruleStates, "tenant-default").find((s) => s.ruleId === RANSOMWARE_ID)!;
    const explicit30d = synthesizeMockActivity(ruleStates, "tenant-default", "30d").find((s) => s.ruleId === RANSOMWARE_ID)!;
    expect(defaulted).toEqual(explicit30d);
  });
});
