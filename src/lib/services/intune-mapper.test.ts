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
      model: undefined,
      manufacturer: undefined,
      serialNumber: undefined,
      imei: undefined,
      enrolledDateTime: undefined,
      managementAgent: undefined,
      ownerType: undefined,
      deviceEnrollmentType: undefined,
      totalStorageBytes: undefined,
      freeStorageBytes: undefined,
      deviceCategory: undefined,
      azureADDeviceId: undefined,
      jailBroken: undefined,
      complianceGracePeriodExpirationDateTime: undefined,
      wiFiMacAddress: undefined,
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
    expect(mapped.model).toBeUndefined();
    expect(mapped.ownerType).toBeUndefined();
    expect(mapped.totalStorageBytes).toBeUndefined();
  });

  it("maps the extended hardware/enrollment detail fields when present", () => {
    const raw = {
      id: "dev-3",
      complianceState: "compliant",
      model: "Surface Laptop 5",
      manufacturer: "Microsoft",
      serialNumber: "SN-12345",
      imei: "490154203237518",
      enrolledDateTime: "2025-01-15T09:00:00Z",
      managementAgent: "mdm",
      ownerType: "Company",
      deviceEnrollmentType: "windowsAzureADJoin",
      totalStorageSpaceInBytes: 512_000_000_000,
      freeStorageSpaceInBytes: 128_000_000_000,
      deviceCategoryDisplayName: "Executives",
      azureADDeviceId: "aad-device-guid",
      jailBroken: "False",
      complianceGracePeriodExpirationDateTime: "2026-09-01T00:00:00Z",
      wiFiMacAddress: "00:11:22:33:44:55",
    };
    const mapped = mapManagedDeviceToIntuneDevice(raw);
    expect(mapped.model).toBe("Surface Laptop 5");
    expect(mapped.manufacturer).toBe("Microsoft");
    expect(mapped.serialNumber).toBe("SN-12345");
    expect(mapped.imei).toBe("490154203237518");
    expect(mapped.enrolledDateTime).toBe("2025-01-15T09:00:00Z");
    expect(mapped.managementAgent).toBe("mdm");
    expect(mapped.ownerType).toBe("company");
    expect(mapped.deviceEnrollmentType).toBe("windowsAzureADJoin");
    expect(mapped.totalStorageBytes).toBe(512_000_000_000);
    expect(mapped.freeStorageBytes).toBe(128_000_000_000);
    expect(mapped.deviceCategory).toBe("Executives");
    expect(mapped.azureADDeviceId).toBe("aad-device-guid");
    expect(mapped.jailBroken).toBe("False");
    expect(mapped.complianceGracePeriodExpirationDateTime).toBe("2026-09-01T00:00:00Z");
    expect(mapped.wiFiMacAddress).toBe("00:11:22:33:44:55");
  });

  it("falls back to 'unknown' ownerType for an unrecognized raw value", () => {
    expect(mapManagedDeviceToIntuneDevice({ id: "dev-4", ownerType: "somethingElse" }).ownerType).toBe("unknown");
  });
});
