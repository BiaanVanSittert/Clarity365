import { describe, it, expect } from "vitest";
import {
  normalizeOperatingSystem,
  normalizeComplianceState,
  deriveAntivirusStatus,
  deriveEdrOnboardingState,
  mapManagedDeviceToIntuneDevice,
} from "./intune-mapper";

describe("normalizeOperatingSystem", () => {
  it("maps known Graph OS strings case-insensitively", () => {
    expect(normalizeOperatingSystem("Windows")).toBe("Windows");
    expect(normalizeOperatingSystem("macOS")).toBe("macOS");
    expect(normalizeOperatingSystem("iOS")).toBe("iOS");
    expect(normalizeOperatingSystem("ANDROID")).toBe("Android");
    expect(normalizeOperatingSystem("linux")).toBe("Linux");
  });

  it("defaults unrecognized or missing values to Windows rather than throwing", () => {
    expect(normalizeOperatingSystem("AndroidEnterprise")).toBe("Windows");
    expect(normalizeOperatingSystem(undefined)).toBe("Windows");
    expect(normalizeOperatingSystem(null)).toBe("Windows");
  });
});

describe("normalizeComplianceState", () => {
  it("maps known Graph compliance states case-insensitively", () => {
    expect(normalizeComplianceState("compliant")).toBe("compliant");
    expect(normalizeComplianceState("noncompliant")).toBe("noncompliant");
    expect(normalizeComplianceState("Conflict")).toBe("conflict");
    expect(normalizeComplianceState("inGracePeriod")).toBe("inGracePeriod");
  });

  it("folds Graph states outside Clarity365's taxonomy into 'error' rather than miscounting as compliant", () => {
    expect(normalizeComplianceState("configManager")).toBe("error");
    expect(normalizeComplianceState("unknown")).toBe("error");
    expect(normalizeComplianceState("somethingNew")).toBe("error");
    expect(normalizeComplianceState(undefined)).toBe("error");
  });
});

describe("deriveAntivirusStatus / deriveEdrOnboardingState", () => {
  it("treats compliant devices as protected", () => {
    expect(deriveAntivirusStatus("compliant")).toBe("active");
    expect(deriveEdrOnboardingState("compliant")).toBe("onboarded");
  });

  it("treats every non-compliant bucket as needing attention", () => {
    expect(deriveAntivirusStatus("noncompliant")).toBe("outOfDate");
    expect(deriveAntivirusStatus("error")).toBe("outOfDate");
    expect(deriveEdrOnboardingState("inGracePeriod")).toBe("canBeOnboarded");
  });
});

describe("mapManagedDeviceToIntuneDevice", () => {
  it("maps a full raw Graph managedDevice resource", () => {
    const raw = {
      id: "dev-1",
      deviceName: "CONTOSO-LAPTOP-01",
      userPrincipalName: "alex@contoso.com",
      operatingSystem: "Windows",
      osVersion: "10.0.22631",
      complianceState: "compliant",
      isEncrypted: true,
      lastSyncDateTime: "2026-08-20T10:00:00Z",
    };
    expect(mapManagedDeviceToIntuneDevice(raw)).toEqual({
      id: "dev-1",
      deviceName: "CONTOSO-LAPTOP-01",
      userPrincipalName: "alex@contoso.com",
      operatingSystem: "Windows",
      osVersion: "10.0.22631",
      complianceState: "compliant",
      isEncrypted: true,
      antivirusStatus: "active",
      edrOnboardingState: "onboarded",
      lastSyncDateTime: "2026-08-20T10:00:00Z",
    });
  });

  it("fills in safe fallbacks for missing optional fields", () => {
    const mapped = mapManagedDeviceToIntuneDevice({ id: "dev-2", complianceState: "noncompliant" });
    expect(mapped.deviceName).toBe("Unknown Device");
    expect(mapped.userPrincipalName).toBe("");
    expect(mapped.isEncrypted).toBe(false);
    expect(mapped.antivirusStatus).toBe("outOfDate");
    expect(mapped.edrOnboardingState).toBe("canBeOnboarded");
    expect(typeof mapped.lastSyncDateTime).toBe("string");
  });
});
