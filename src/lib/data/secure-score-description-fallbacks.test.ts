import { describe, it, expect } from "vitest";
import { SECURE_SCORE_DESCRIPTION_FALLBACKS, getSecureScoreDescriptionFallback } from "./secure-score-description-fallbacks";

describe("getSecureScoreDescriptionFallback", () => {
  it("returns real text for the one control confirmed live to have no Microsoft-provided description", () => {
    expect(getSecureScoreDescriptionFallback("mdo_autoforwardingmode")).toContain("forwarding");
  });

  it("returns undefined for a control that already has a real Microsoft description", () => {
    expect(getSecureScoreDescriptionFallback("meeting_restrictanonymousjoin_v1")).toBeUndefined();
  });
});

describe("SECURE_SCORE_DESCRIPTION_FALLBACKS data quality", () => {
  it("stays a short, deliberately scoped list - only controls confirmed live to lack a description", () => {
    expect(Object.keys(SECURE_SCORE_DESCRIPTION_FALLBACKS)).toEqual(["mdo_autoforwardingmode"]);
  });

  it("gives every entry non-empty, real prose (not a placeholder)", () => {
    for (const [controlId, text] of Object.entries(SECURE_SCORE_DESCRIPTION_FALLBACKS)) {
      expect(text.length, controlId).toBeGreaterThan(30);
      expect(text, controlId).not.toMatch(/no description available/i);
    }
  });
});
