import { describe, it, expect } from "vitest";
import {
  normalizeCategory,
  normalizeCostOrImpact,
  deriveControlStatus,
  normalizeActionType,
  mapSecureScoreControl,
  buildSecureScoreHistory,
  computeScoreDelta,
  extractIndustryBenchmark,
} from "./secure-score-mapper";

describe("normalizeCategory", () => {
  it("maps known Graph categories case-insensitively", () => {
    expect(normalizeCategory("Identity")).toBe("Identity");
    expect(normalizeCategory("device")).toBe("Device");
    expect(normalizeCategory("APPS")).toBe("Apps");
    expect(normalizeCategory("Data")).toBe("Data");
  });

  it("maps Infrastructure, a real Graph category, to its own bucket", () => {
    expect(normalizeCategory("Infrastructure")).toBe("Infrastructure");
    expect(normalizeCategory("INFRASTRUCTURE")).toBe("Infrastructure");
  });

  it("falls back to Apps for categories outside the current taxonomy", () => {
    expect(normalizeCategory("SomethingUnrecognized")).toBe("Apps");
    expect(normalizeCategory(undefined)).toBe("Apps");
  });
});

describe("normalizeCostOrImpact", () => {
  it("maps known values case-insensitively", () => {
    expect(normalizeCostOrImpact("low")).toBe("Low");
    expect(normalizeCostOrImpact("High")).toBe("High");
    expect(normalizeCostOrImpact("moderate")).toBe("Moderate");
  });

  it("treats Graph's 'Medium' as an alias for Moderate", () => {
    expect(normalizeCostOrImpact("Medium")).toBe("Moderate");
    expect(normalizeCostOrImpact("medium")).toBe("Moderate");
  });

  it("surfaces Graph's own 'Unknown' value as Unknown rather than guessing a severity", () => {
    expect(normalizeCostOrImpact("Unknown")).toBe("Unknown");
  });

  it("defaults unrecognized or missing values to Unknown, not Moderate - confirmed live this is Graph's own value for most controls", () => {
    expect(normalizeCostOrImpact("weird")).toBe("Unknown");
    expect(normalizeCostOrImpact(undefined)).toBe("Unknown");
    expect(normalizeCostOrImpact(null)).toBe("Unknown");
  });
});

describe("deriveControlStatus", () => {
  it("marks a fully-achieved control as Completed", () => {
    expect(deriveControlStatus(50, 50)).toBe("Completed");
  });

  it("marks a zero-score control as Unresolved", () => {
    expect(deriveControlStatus(0, 35)).toBe("Unresolved");
  });

  it("marks a partial score as Partial", () => {
    expect(deriveControlStatus(15, 30)).toBe("Partial");
  });

  it("treats a control with no max score as Unresolved rather than dividing by zero", () => {
    expect(deriveControlStatus(0, 0)).toBe("Unresolved");
  });
});

describe("normalizeActionType", () => {
  it("maps known Graph action types", () => {
    expect(normalizeActionType("Config")).toBe("Configuration");
    expect(normalizeActionType("Behavior")).toBe("Requirement");
    expect(normalizeActionType("PurchaseService")).toBe("Policy");
  });

  it("defaults unrecognized values to Configuration", () => {
    expect(normalizeActionType("Unknown")).toBe("Configuration");
  });
});

describe("mapSecureScoreControl", () => {
  it("joins a score entry with its control profile", () => {
    const control = mapSecureScoreControl(
      { controlName: "mfaAdmins", score: 40, controlCategory: "Identity", description: "Requires MFA for admins.", implementationStatus: "current status: Off" },
      {
        id: "mfaAdmins",
        title: "Require MFA for admins",
        maxScore: 50,
        implementationCost: "Low",
        userImpact: "Low",
        actionType: "Config",
        remediation: "Enable MFA for all admin roles.",
        actionUrl: "https://entra.microsoft.com/",
        remediationImpact: "Admins must complete MFA at sign-in.",
        threats: ["Account breach"],
      }
    );
    expect(control).toEqual({
      id: "mfaAdmins",
      title: "Require MFA for admins",
      category: "Identity",
      scoreCurrent: 40,
      scoreMax: 50,
      implementationCost: "Low",
      userImpact: "Low",
      status: "Partial",
      actionType: "Configuration",
      description: "Requires MFA for admins.",
      remediationSummary: "Enable MFA for all admin roles.",
      actionUrl: "https://entra.microsoft.com/",
      remediationImpact: "Admins must complete MFA at sign-in.",
      threats: ["Account breach"],
      implementationStatus: "current status: Off",
      deployment: { type: "guided" },
    });
  });

  it("falls back gracefully when no matching control profile is found", () => {
    const control = mapSecureScoreControl({ controlName: "orphanControl", score: 0 }, undefined);
    expect(control.title).toBe("orphanControl");
    expect(control.scoreMax).toBe(0);
    expect(control.status).toBe("Unresolved");
    expect(control.remediationSummary).toBe("No remediation guidance available for this control.");
    expect(control.description).toBe("No description available for this control.");
    expect(control.actionUrl).toBeUndefined();
    expect(control.deployment).toEqual({ type: "manual_only" });
  });

  it("uses the curated description fallback when Graph's own description is empty but a fallback exists for this controlName", () => {
    const control = mapSecureScoreControl({ controlName: "mdo_autoforwardingmode", score: 1 }, { id: "mdo_autoforwardingmode", maxScore: 1 });
    expect(control.description).toContain("forwarding");
    expect(control.description).not.toBe("No description available for this control.");
  });

  it("prefers Graph's own live description over the curated fallback when both are available", () => {
    const control = mapSecureScoreControl(
      { controlName: "mdo_autoforwardingmode", score: 1, description: "Live Microsoft-provided text." },
      { id: "mdo_autoforwardingmode", maxScore: 1 }
    );
    expect(control.description).toBe("Live Microsoft-provided text.");
  });

  it("handles a remediation field that's an object instead of a string", () => {
    const control = mapSecureScoreControl(
      { controlName: "c1", score: 10 },
      { id: "c1", maxScore: 10, remediation: { description: "Do the thing." } }
    );
    expect(control.remediationSummary).toBe("Do the thing.");
  });

  it("defaults to guided deployment when a control has an actionUrl but no live-verified auto-deploy mapping", () => {
    const control = mapSecureScoreControl(
      { controlName: "spo_idle_session_timeout", score: 0 },
      { id: "spo_idle_session_timeout", maxScore: 1, actionUrl: "https://admin.microsoft.com/" }
    );
    expect(control.deployment).toEqual({ type: "guided" });
  });

  it("upgrades deployment to auto for a controlName with a confirmed baseline mapping", () => {
    const control = mapSecureScoreControl(
      { controlName: "BlockLegacyAuthentication", score: 0 },
      { id: "BlockLegacyAuthentication", maxScore: 20, actionUrl: "https://entra.microsoft.com/" }
    );
    expect(control.deployment).toEqual({ type: "auto", clarity365Action: "CA01" });
  });

  it("omits optional fields entirely rather than storing empty strings/arrays", () => {
    const control = mapSecureScoreControl(
      { controlName: "c2", score: 0 },
      { id: "c2", maxScore: 5, remediationImpact: "", threats: [] }
    );
    expect(control.remediationImpact).toBeUndefined();
    expect(control.threats).toBeUndefined();
    expect(control.implementationStatus).toBeUndefined();
  });
});

describe("buildSecureScoreHistory", () => {
  it("returns points in chronological (oldest-first) order regardless of input order", () => {
    const history = buildSecureScoreHistory([
      { createdDateTime: "2026-08-20T00:00:00Z", currentScore: 420, maxScore: 650 },
      { createdDateTime: "2026-06-20T00:00:00Z", currentScore: 390, maxScore: 650 },
      { createdDateTime: "2026-07-20T00:00:00Z", currentScore: 405, maxScore: 650 },
    ]);
    expect(history.map((h) => h.date)).toEqual(["2026-06-20", "2026-07-20", "2026-08-20"]);
    expect(history[2].percentage).toBeCloseTo(64.6, 1);
  });

  it("drops entries with no max score to avoid a divide-by-zero percentage", () => {
    const history = buildSecureScoreHistory([{ createdDateTime: "2026-08-20T00:00:00Z", currentScore: 0, maxScore: 0 }]);
    expect(history).toEqual([]);
  });
});

describe("computeScoreDelta", () => {
  const entries = [
    { createdDateTime: "2026-08-20T00:00:00Z", currentScore: 65, maxScore: 100 },
    { createdDateTime: "2026-07-21T00:00:00Z", currentScore: 60, maxScore: 100 },
    { createdDateTime: "2026-05-22T00:00:00Z", currentScore: 50, maxScore: 100 },
  ];

  it("computes the percentage-point delta against ~30 days ago", () => {
    expect(computeScoreDelta(entries, 30)).toBeCloseTo(5, 1);
  });

  it("computes the percentage-point delta against ~90 days ago, falling back to the oldest entry", () => {
    expect(computeScoreDelta(entries, 90)).toBeCloseTo(15, 1);
  });

  it("returns 0 for an empty history", () => {
    expect(computeScoreDelta([], 30)).toBe(0);
  });
});

describe("extractIndustryBenchmark", () => {
  it("picks the AllTenants comparison basis when present", () => {
    expect(
      extractIndustryBenchmark([
        { basis: "TotalSeats", averageScore: 55 },
        { basis: "AllTenants", averageScore: 61.2 },
      ])
    ).toBe(61.2);
  });

  it("falls back to the first entry when AllTenants isn't present", () => {
    expect(extractIndustryBenchmark([{ basis: "TotalSeats", averageScore: 55 }])).toBe(55);
  });

  it("returns 0 for missing/empty input", () => {
    expect(extractIndustryBenchmark(undefined)).toBe(0);
    expect(extractIndustryBenchmark([])).toBe(0);
  });
});
