import { describe, it, expect } from "vitest";
import {
  normalizeOperatingSystem,
  normalizeComplianceState,
  deriveAntivirusStatus,
  deriveEdrOnboardingState,
  mapManagedDeviceToIntuneDevice,
  applyRealEdrOnboardingStates,
  mapMdeConnectorSettings,
  mapAtpOnboardingDeviceState,
  mapDeviceComplianceSettingStateRow,
  applyDeviceComplianceReasons,
} from "./intune-mapper";
import { IntuneDevice, AtpOnboardingDeviceState } from "../types";

function makeDevice(overrides: Partial<IntuneDevice> = {}): IntuneDevice {
  return {
    id: "dev-1",
    deviceName: "DESKTOP-ABC123",
    userPrincipalName: "user@contoso.com",
    operatingSystem: "Windows",
    osVersion: "10.0.19045",
    complianceState: "noncompliant",
    isEncrypted: true,
    antivirusStatus: "active",
    edrOnboardingState: "canBeOnboarded",
    lastSyncDateTime: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

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
      managedDeviceOwnerType: "Company",
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
    expect(mapManagedDeviceToIntuneDevice({ id: "dev-4", managedDeviceOwnerType: "somethingElse" }).ownerType).toBe("unknown");
  });
});

describe("applyRealEdrOnboardingStates", () => {
  it("overrides the compliance-derived approximation with real ATP telemetry, matched by device name", () => {
    const devices = [makeDevice({ deviceName: "DESKTOP-ABC123", edrOnboardingState: "canBeOnboarded" })];
    const onboarding: AtpOnboardingDeviceState[] = [{ deviceName: "desktop-abc123", state: "compliant" }];
    const result = applyRealEdrOnboardingStates(devices, onboarding);
    expect(result[0].edrOnboardingState).toBe("onboarded");
  });

  it("maps every ATP state to the right IntuneDevice edrOnboardingState value", () => {
    const cases: [AtpOnboardingDeviceState["state"], IntuneDevice["edrOnboardingState"]][] = [
      ["compliant", "onboarded"],
      ["remediated", "onboarded"],
      ["notApplicable", "unsupported"],
      ["nonCompliant", "canBeOnboarded"],
      ["notAssigned", "canBeOnboarded"],
      ["error", "error"],
      ["conflict", "error"],
      ["unknown", "canBeOnboarded"],
    ];
    for (const [atpState, expected] of cases) {
      const devices = [makeDevice({ deviceName: "DEV", edrOnboardingState: "canBeOnboarded" })];
      const result = applyRealEdrOnboardingStates(devices, [{ deviceName: "DEV", state: atpState }]);
      expect(result[0].edrOnboardingState).toBe(expected);
    }
  });

  it("leaves the compliance-derived approximation alone for a device with no matching onboarding record", () => {
    const devices = [makeDevice({ deviceName: "UNMATCHED-DEVICE", edrOnboardingState: "canBeOnboarded" })];
    const result = applyRealEdrOnboardingStates(devices, [{ deviceName: "OTHER-DEVICE", state: "compliant" }]);
    expect(result[0].edrOnboardingState).toBe("canBeOnboarded");
  });

  it("returns the original devices array untouched when there is no onboarding data at all", () => {
    const devices = [makeDevice()];
    expect(applyRealEdrOnboardingStates(devices, undefined)).toBe(devices);
    expect(applyRealEdrOnboardingStates(devices, [])).toBe(devices);
  });
});

describe("mapDeviceComplianceSettingStateRow", () => {
  it("maps a nonCompliant row to a DeviceComplianceReason", () => {
    const result = mapDeviceComplianceSettingStateRow({
      deviceName: "DESKTOP-ABC123",
      settingName: "Require BitLocker",
      state: "nonCompliant",
    });
    expect(result).toEqual({
      deviceName: "DESKTOP-ABC123",
      reason: { settingName: "Require BitLocker", state: "nonCompliant" },
    });
  });

  it("maps error and conflict rows too", () => {
    expect(mapDeviceComplianceSettingStateRow({ deviceName: "D1", settingName: "S1", state: "error" })?.reason.state).toBe("error");
    expect(mapDeviceComplianceSettingStateRow({ deviceName: "D1", settingName: "S1", state: "conflict" })?.reason.state).toBe("conflict");
  });

  it("returns null for compliant/remediated/notApplicable/unknown - not an actionable finding", () => {
    for (const state of ["compliant", "remediated", "notApplicable", "unknown"]) {
      expect(mapDeviceComplianceSettingStateRow({ deviceName: "D1", settingName: "S1", state })).toBeNull();
    }
  });

  it("returns null when deviceName or settingName is missing", () => {
    expect(mapDeviceComplianceSettingStateRow({ settingName: "S1", state: "nonCompliant" })).toBeNull();
    expect(mapDeviceComplianceSettingStateRow({ deviceName: "D1", state: "nonCompliant" })).toBeNull();
  });

  it("is case-insensitive on the state value", () => {
    expect(mapDeviceComplianceSettingStateRow({ deviceName: "D1", settingName: "S1", state: "NonCompliant" })?.reason.state).toBe("nonCompliant");
  });
});

describe("applyDeviceComplianceReasons", () => {
  it("groups multiple reason rows for the same device, matched by device name case-insensitively", () => {
    const devices = [makeDevice({ deviceName: "DESKTOP-ABC123" })];
    const rows = [
      { deviceName: "desktop-abc123", reason: { settingName: "Require BitLocker", state: "nonCompliant" as const } },
      { deviceName: "desktop-abc123", reason: { settingName: "Require TPM", state: "nonCompliant" as const } },
    ];
    const result = applyDeviceComplianceReasons(devices, rows);
    expect(result[0].nonComplianceReasons).toEqual([
      { settingName: "Require BitLocker", state: "nonCompliant" },
      { settingName: "Require TPM", state: "nonCompliant" },
    ]);
  });

  it("leaves nonComplianceReasons undefined for a device with no matching rows", () => {
    const devices = [makeDevice({ deviceName: "UNMATCHED-DEVICE" })];
    const result = applyDeviceComplianceReasons(devices, [
      { deviceName: "OTHER-DEVICE", reason: { settingName: "Require BitLocker", state: "nonCompliant" } },
    ]);
    expect(result[0].nonComplianceReasons).toBeUndefined();
  });

  it("returns the original devices array untouched when there are no reason rows at all", () => {
    const devices = [makeDevice()];
    expect(applyDeviceComplianceReasons(devices, undefined)).toBe(devices);
    expect(applyDeviceComplianceReasons(devices, [])).toBe(devices);
  });
});

describe("mapMdeConnectorSettings", () => {
  it("maps every v1.0 and beta-only property, coercing missing booleans to false", () => {
    const mapped = mapMdeConnectorSettings({
      id: "connector-1",
      lastHeartbeatDateTime: "2026-01-01T00:00:00Z",
      partnerState: "enabled",
      microsoftDefenderForEndpointAttachEnabled: true,
      androidEnabled: true,
      macEnabled: true,
      macDeviceBlockedOnMissingPartnerData: false,
    });
    expect(mapped.id).toBe("connector-1");
    expect(mapped.partnerState).toBe("enabled");
    expect(mapped.microsoftDefenderForEndpointAttachEnabled).toBe(true);
    expect(mapped.androidEnabled).toBe(true);
    expect(mapped.iosEnabled).toBe(false);
    expect(mapped.macEnabled).toBe(true);
  });

  it("defaults partnerState to 'unavailable' when missing", () => {
    expect(mapMdeConnectorSettings({ id: "connector-2" }).partnerState).toBe("unavailable");
  });
});

describe("mapAtpOnboardingDeviceState", () => {
  it("maps a raw device onboarding record", () => {
    const mapped = mapAtpOnboardingDeviceState({
      deviceName: "DESKTOP-XYZ",
      userPrincipalName: "user@contoso.com",
      platformType: "desktop",
      state: "nonCompliant",
    });
    expect(mapped).toEqual({
      deviceName: "DESKTOP-XYZ",
      userPrincipalName: "user@contoso.com",
      platformType: "desktop",
      state: "nonCompliant",
    });
  });

  it("defaults state to 'unknown' when missing", () => {
    expect(mapAtpOnboardingDeviceState({ deviceName: "DEV" }).state).toBe("unknown");
  });
});
