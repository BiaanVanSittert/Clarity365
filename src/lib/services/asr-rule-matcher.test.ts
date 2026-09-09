import { describe, it, expect } from "vitest";
import { classifyAsrRuleTier, ASR_TIER_SEVERITY } from "./asr-rule-matcher";

describe("classifyAsrRuleTier", () => {
  it("classifies a Block-mode rule as protected regardless of category", () => {
    expect(classifyAsrRuleTier({ mode: "block", isStandardProtection: true })).toBe("protected");
    expect(classifyAsrRuleTier({ mode: "block", isStandardProtection: false })).toBe("protected");
  });

  it("classifies Audit or Warn mode as in_progress regardless of category", () => {
    expect(classifyAsrRuleTier({ mode: "audit", isStandardProtection: true })).toBe("in_progress");
    expect(classifyAsrRuleTier({ mode: "warn", isStandardProtection: false })).toBe("in_progress");
  });

  it("classifies a not-configured Standard Protection rule as critical", () => {
    expect(classifyAsrRuleTier({ mode: "not_configured", isStandardProtection: true })).toBe("critical");
  });

  it("classifies a not-configured non-standard rule as a gap, not critical", () => {
    expect(classifyAsrRuleTier({ mode: "not_configured", isStandardProtection: false })).toBe("gap");
  });

  it("orders severity worst first: critical, gap, in_progress, protected", () => {
    expect(ASR_TIER_SEVERITY.critical).toBeLessThan(ASR_TIER_SEVERITY.gap);
    expect(ASR_TIER_SEVERITY.gap).toBeLessThan(ASR_TIER_SEVERITY.in_progress);
    expect(ASR_TIER_SEVERITY.in_progress).toBeLessThan(ASR_TIER_SEVERITY.protected);
  });
});
