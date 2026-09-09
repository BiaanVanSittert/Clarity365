import { describe, it, expect } from "vitest";
import { classifyPrivilegedAccessTier } from "./privileged-access-risk-tier";

describe("classifyPrivilegedAccessTier", () => {
  it("classifies a disabled account as disabled regardless of every other flag", () => {
    expect(
      classifyPrivilegedAccessTier({ accountEnabled: false, mfaRegistered: false, isLicensedForDailyUse: true })
    ).toBe("disabled");
  });

  it("classifies an admin with no MFA as critical", () => {
    expect(
      classifyPrivilegedAccessTier({ accountEnabled: true, mfaRegistered: false, isLicensedForDailyUse: false })
    ).toBe("critical");
  });

  it("critical overrides the license axis: no MFA plus a daily-use license is still critical, not red", () => {
    expect(
      classifyPrivilegedAccessTier({ accountEnabled: true, mfaRegistered: false, isLicensedForDailyUse: true })
    ).toBe("critical");
  });

  it("classifies an MFA-registered admin with a daily-use license as red", () => {
    expect(
      classifyPrivilegedAccessTier({ accountEnabled: true, mfaRegistered: true, isLicensedForDailyUse: true })
    ).toBe("red");
  });

  it("classifies an MFA-registered admin with no daily-use license as green", () => {
    expect(
      classifyPrivilegedAccessTier({ accountEnabled: true, mfaRegistered: true, isLicensedForDailyUse: false })
    ).toBe("green");
  });
});
