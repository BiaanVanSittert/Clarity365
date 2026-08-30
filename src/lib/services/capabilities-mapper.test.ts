import { describe, it, expect } from "vitest";
import { mapSubscribedSkusToCapabilities } from "./capabilities-mapper";

describe("capabilities-mapper", () => {
  it("detects M365 E5 / Entra P2 capabilities from SPE_E5 SKU", () => {
    const skus = [
      {
        skuPartNumber: "SPE_E5",
        capabilityStatus: "Enabled",
        consumedUnits: 50,
      },
    ];

    const caps = mapSubscribedSkusToCapabilities(skus);
    const entra = caps.find((c) => c.id === "cap-entra");
    const intune = caps.find((c) => c.id === "cap-intune");
    const mde = caps.find((c) => c.id === "cap-mde");
    const mdo = caps.find((c) => c.id === "cap-mdo");

    expect(entra?.licensed).toBe(true);
    expect(entra?.tier).toContain("P2");
    expect(intune?.licensed).toBe(true);
    expect(mde?.licensed).toBe(true);
    expect(mdo?.licensed).toBe(true);
  });

  it("handles empty or standard business skus without P2 features", () => {
    const skus = [
      {
        skuPartNumber: "O365_BUSINESS_ESSENTIALS",
        capabilityStatus: "Enabled",
        consumedUnits: 10,
      },
    ];

    const caps = mapSubscribedSkusToCapabilities(skus);
    const entra = caps.find((c) => c.id === "cap-entra");
    expect(entra?.licensed).toBe(false);
    expect(entra?.tier).toContain("Free");
  });
});
