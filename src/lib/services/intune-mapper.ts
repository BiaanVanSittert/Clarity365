import { IntuneDevice } from "../types";

// Maps a raw Microsoft Graph `managedDevice` resource (GET
// /deviceManagement/managedDevices) into Clarity365's IntuneDevice shape.
// Pulled out of graph-client.ts so the OS/compliance-state normalization
// rules are unit-testable without a live Graph response driving them.

const OS_MAP: Record<string, IntuneDevice["operatingSystem"]> = {
  windows: "Windows",
  macos: "macOS",
  ios: "iOS",
  android: "Android",
  linux: "Linux",
};

export function normalizeOperatingSystem(raw: string | undefined | null): IntuneDevice["operatingSystem"] {
  const lower = (raw || "").toLowerCase();
  // Intune fleets skew overwhelmingly Windows; that's a safer default for an
  // unrecognized enrollment-type string than throwing mid-sync.
  return OS_MAP[lower] || "Windows";
}

const COMPLIANCE_STATE_MAP: Record<string, IntuneDevice["complianceState"]> = {
  compliant: "compliant",
  noncompliant: "noncompliant",
  conflict: "conflict",
  error: "error",
  ingraceperiod: "inGracePeriod",
  // Graph can also report "configManager" (co-managed devices) and "unknown" -
  // neither has a matching bucket in Clarity365's taxonomy yet, so they fold
  // into "error" rather than being silently miscounted as compliant.
  configmanager: "error",
  unknown: "error",
};

export function normalizeComplianceState(raw: string | undefined | null): IntuneDevice["complianceState"] {
  const lower = (raw || "").toLowerCase();
  return COMPLIANCE_STATE_MAP[lower] || "error";
}

// antivirusStatus/edrOnboardingState aren't fields on the managedDevices
// resource - real per-device Microsoft Defender AV/EDR health requires either
// an extra Graph beta call per device or Microsoft Defender for Endpoint's
// separate API (a distinct app registration/permission model). As a
// documented proxy: a compliant device is assumed to have AV active and EDR
// onboarded; anything else is assumed to need attention. This is an
// approximation derived from compliance state, not live Defender telemetry.
export function deriveAntivirusStatus(complianceState: IntuneDevice["complianceState"]): IntuneDevice["antivirusStatus"] {
  return complianceState === "compliant" ? "active" : "outOfDate";
}

export function deriveEdrOnboardingState(complianceState: IntuneDevice["complianceState"]): IntuneDevice["edrOnboardingState"] {
  return complianceState === "compliant" ? "onboarded" : "canBeOnboarded";
}

const OWNER_TYPE_MAP: Record<string, NonNullable<IntuneDevice["ownerType"]>> = {
  company: "company",
  personal: "personal",
};

function normalizeOwnerType(raw: string | undefined | null): IntuneDevice["ownerType"] {
  if (!raw) return undefined;
  return OWNER_TYPE_MAP[raw.toLowerCase()] || "unknown";
}

function numberOrUndefined(raw: any): number | undefined {
  return typeof raw === "number" ? raw : undefined;
}

export function mapManagedDeviceToIntuneDevice(raw: any): IntuneDevice {
  const complianceState = normalizeComplianceState(raw.complianceState);
  return {
    id: raw.id,
    deviceName: raw.deviceName || "Unknown Device",
    userPrincipalName: raw.userPrincipalName || "",
    operatingSystem: normalizeOperatingSystem(raw.operatingSystem),
    osVersion: raw.osVersion || "",
    complianceState,
    isEncrypted: !!raw.isEncrypted,
    antivirusStatus: deriveAntivirusStatus(complianceState),
    edrOnboardingState: deriveEdrOnboardingState(complianceState),
    lastSyncDateTime: raw.lastSyncDateTime || new Date().toISOString(),
    model: raw.model || undefined,
    manufacturer: raw.manufacturer || undefined,
    serialNumber: raw.serialNumber || undefined,
    imei: raw.imei || undefined,
    enrolledDateTime: raw.enrolledDateTime || undefined,
    managementAgent: raw.managementAgent || undefined,
    ownerType: normalizeOwnerType(raw.managedDeviceOwnerType),
    deviceEnrollmentType: raw.deviceEnrollmentType || undefined,
    totalStorageBytes: numberOrUndefined(raw.totalStorageSpaceInBytes),
    freeStorageBytes: numberOrUndefined(raw.freeStorageSpaceInBytes),
    deviceCategory: raw.deviceCategoryDisplayName || undefined,
    azureADDeviceId: raw.azureADDeviceId || undefined,
    jailBroken: raw.jailBroken || undefined,
    complianceGracePeriodExpirationDateTime: raw.complianceGracePeriodExpirationDateTime || undefined,
    wiFiMacAddress: raw.wiFiMacAddress || undefined,
  };
}
