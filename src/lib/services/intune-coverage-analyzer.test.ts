import { describe, it, expect } from "vitest";
import { findUsersMissingIntuneDevice, findDevicesMissingEdr, computeIntuneCoverageGaps } from "./intune-coverage-analyzer";
import { TenantAccountSummary, IntuneDevice } from "../types";

function makeUser(overrides: Partial<TenantAccountSummary["users"][number]> = {}): TenantAccountSummary["users"][number] {
  return {
    id: "usr-1",
    userPrincipalName: "alice@contoso.com",
    displayName: "Alice",
    classification: "licensed",
    licenses: ["SPE_E5"],
    accountEnabled: true,
    department: "Sales",
    createdDateTime: "2024-01-01T00:00:00Z",
    ...overrides,
  };
}

function makeDevice(overrides: Partial<IntuneDevice> = {}): IntuneDevice {
  return {
    id: "dev-1",
    deviceName: "DESKTOP-1",
    userPrincipalName: "alice@contoso.com",
    operatingSystem: "Windows",
    osVersion: "10.0.19045",
    complianceState: "compliant",
    isEncrypted: true,
    antivirusStatus: "active",
    edrOnboardingState: "onboarded",
    lastSyncDateTime: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("findUsersMissingIntuneDevice", () => {
  it("flags a licensed, enabled user with no enrolled device", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser()], []);
    expect(gaps).toHaveLength(1);
    expect(gaps[0].userPrincipalName).toBe("alice@contoso.com");
  });

  it("does not flag a licensed user who has an enrolled device", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser()], [makeDevice({ userPrincipalName: "alice@contoso.com" })]);
    expect(gaps).toHaveLength(0);
  });

  it("matches the user/device join case-insensitively", () => {
    const gaps = findUsersMissingIntuneDevice(
      [makeUser({ userPrincipalName: "Alice@Contoso.com" })],
      [makeDevice({ userPrincipalName: "alice@CONTOSO.com" })]
    );
    expect(gaps).toHaveLength(0);
  });

  it("does not flag an unlicensed or disabled account", () => {
    const gaps = findUsersMissingIntuneDevice(
      [makeUser({ classification: "unlicensed_active" }), makeUser({ userPrincipalName: "bob@contoso.com", accountEnabled: false })],
      []
    );
    expect(gaps).toHaveLength(0);
  });

  it("does not flag a licensed user whose own SKU doesn't include Intune at all (regression: was flagging every licensed user regardless of SKU)", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser({ licenses: ["EXCHANGESTANDARD"] })], []);
    expect(gaps).toHaveLength(0);
  });

  it("still flags a licensed user on a genuinely Intune-capable SKU (SPB - Business Premium)", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser({ licenses: ["SPB"] })], []);
    expect(gaps).toHaveLength(1);
  });

  it("does not flag a user on the legacy Business Standard SKU, which despite its name is not Business Premium and has no Intune", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser({ licenses: ["O365_BUSINESS_PREMIUM"] })], []);
    expect(gaps).toHaveLength(0);
  });

  it("flags a user with multiple licenses as long as at least one of them is Intune-capable", () => {
    const gaps = findUsersMissingIntuneDevice([makeUser({ licenses: ["EXCHANGESTANDARD", "SPE_E3"] })], []);
    expect(gaps).toHaveLength(1);
  });
});

describe("findDevicesMissingEdr", () => {
  it("flags a device that can be onboarded but isn't", () => {
    const gaps = findDevicesMissingEdr([makeDevice({ edrOnboardingState: "canBeOnboarded" })]);
    expect(gaps).toHaveLength(1);
  });

  it("flags a device reporting an EDR error", () => {
    const gaps = findDevicesMissingEdr([makeDevice({ edrOnboardingState: "error" })]);
    expect(gaps).toHaveLength(1);
  });

  it("does not flag an already-onboarded device", () => {
    expect(findDevicesMissingEdr([makeDevice({ edrOnboardingState: "onboarded" })])).toHaveLength(0);
  });

  it("does not flag a device MDE genuinely can't support", () => {
    expect(findDevicesMissingEdr([makeDevice({ edrOnboardingState: "unsupported" })])).toHaveLength(0);
  });
});

describe("computeIntuneCoverageGaps", () => {
  it("combines both lenses into one result", () => {
    const result = computeIntuneCoverageGaps(
      [makeUser({ userPrincipalName: "nodev@contoso.com" })],
      [makeDevice({ userPrincipalName: "other@contoso.com", edrOnboardingState: "canBeOnboarded" })]
    );
    expect(result.usersWithoutIntuneDevice).toHaveLength(1);
    expect(result.devicesWithoutEdr).toHaveLength(1);
  });
});
