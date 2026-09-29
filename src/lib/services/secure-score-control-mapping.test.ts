import { describe, it, expect } from "vitest";
import { applyAutoDeployMapping, SECURE_SCORE_AUTO_DEPLOY_MAP } from "./secure-score-control-mapping";

describe("applyAutoDeployMapping", () => {
  it("overrides to auto with the mapped baseline code for a known controlName", () => {
    expect(applyAutoDeployMapping("BlockLegacyAuthentication", { type: "guided" })).toEqual({
      type: "auto",
      clarity365Action: "CA01",
    });
  });

  it("covers every confirmed live mapping", () => {
    expect(applyAutoDeployMapping("MFARegistrationV2", { type: "manual_only" })).toEqual({ type: "auto", clarity365Action: "CA02" });
    expect(applyAutoDeployMapping("AdminMFAV2", { type: "guided" })).toEqual({ type: "auto", clarity365Action: "CA03" });
    expect(applyAutoDeployMapping("SigninRiskPolicy", { type: "guided" })).toEqual({ type: "auto", clarity365Action: "CA06" });
    expect(applyAutoDeployMapping("UserRiskPolicy", { type: "guided" })).toEqual({ type: "auto", clarity365Action: "CA07" });
  });

  it("leaves the default deployment untouched for an unmapped controlName", () => {
    const guided = { type: "guided" as const };
    expect(applyAutoDeployMapping("meeting_restrictanonymousjoin_v1", guided)).toBe(guided);
  });

  it("does not map Device-category EDR/AV/BitLocker telemetry controls to auto - those score per-device compliance, not policy existence", () => {
    const guided = { type: "guided" as const };
    expect(applyAutoDeployMapping("scid_2010", guided)).toBe(guided);
    expect(applyAutoDeployMapping("scid_2090", guided)).toBe(guided);
  });

  it("stays a short, deliberately conservative allowlist", () => {
    expect(Object.keys(SECURE_SCORE_AUTO_DEPLOY_MAP).sort()).toEqual(
      ["AdminMFAV2", "BlockLegacyAuthentication", "MFARegistrationV2", "SigninRiskPolicy", "UserRiskPolicy"].sort()
    );
  });
});
