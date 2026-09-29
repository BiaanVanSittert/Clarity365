import { IntuneDevice, AtpOnboardingDeviceState, MdeConnectorSettings, DeviceComplianceReason } from "../types";

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

const ATP_STATE_MAP: Record<AtpOnboardingDeviceState["state"], IntuneDevice["edrOnboardingState"]> = {
  compliant: "onboarded",
  remediated: "onboarded",
  notApplicable: "unsupported",
  nonCompliant: "canBeOnboarded",
  notAssigned: "canBeOnboarded",
  error: "error",
  conflict: "error",
  // No real signal yet for this device - keep the friendlier "not yet
  // onboarded" reading rather than alarming with "error" over an absence of
  // data.
  unknown: "canBeOnboarded",
};

// Replaces the compliance-state-derived edrOnboardingState approximation
// (deriveEdrOnboardingState above) with real Microsoft Defender for Endpoint
// telemetry wherever a match exists. Graph's per-device onboarding state
// doesn't carry an Intune managedDevice id, so the join is by device name
// (case-insensitive) - the same best-effort-match convention this app
// already uses elsewhere when Graph doesn't offer a clean foreign key.
// Devices with no matching onboarding record keep the approximation rather
// than being marked unknown/error - a device this app can't cross-reference
// yet shouldn't suddenly look worse than it did before this feature existed.
export function applyRealEdrOnboardingStates(
  devices: IntuneDevice[],
  onboardingStates: AtpOnboardingDeviceState[] | undefined
): IntuneDevice[] {
  if (!onboardingStates || onboardingStates.length === 0) return devices;

  const byDeviceName = new Map<string, AtpOnboardingDeviceState>();
  for (const s of onboardingStates) {
    if (s.deviceName) byDeviceName.set(s.deviceName.toLowerCase(), s);
  }

  return devices.map((device) => {
    const match = byDeviceName.get(device.deviceName.toLowerCase());
    if (!match) return device;
    return { ...device, edrOnboardingState: ATP_STATE_MAP[match.state] ?? device.edrOnboardingState };
  });
}

// Maps one raw deviceComplianceSettingState row (a per-device, per-setting
// compliance result nested under deviceCompliancePolicySettingStateSummaries
// - see ai-context-vault/Optimization/Intune Non-Compliance Reasons Plan.md)
// into Clarity365's shape, or null when the row isn't an actionable
// "reason" (compliant/remediated/notApplicable/unknown - see the comment on
// DeviceComplianceReason itself for why "unknown" is excluded too).
const REASON_STATE_MAP: Record<string, DeviceComplianceReason["state"] | undefined> = {
  noncompliant: "nonCompliant",
  error: "error",
  conflict: "conflict",
};

export function mapDeviceComplianceSettingStateRow(
  raw: any
): { deviceName: string; reason: DeviceComplianceReason } | null {
  const state = REASON_STATE_MAP[(raw?.state || "").toLowerCase()];
  if (!state || !raw?.deviceName || !raw?.settingName) return null;
  return { deviceName: raw.deviceName, reason: { settingName: raw.settingName, state } };
}

// Groups the flat, fleet-wide list of per-setting non-compliance rows by
// device (case-insensitive device name match - deviceComplianceSettingState
// doesn't carry an Intune managedDevice id, and this codebase's own
// applyRealEdrOnboardingStates above already established device-name
// matching as the proven-safe fallback for exactly this class of Graph
// resource) and attaches them to the matching device. Devices with no
// matching row are left untouched (undefined nonComplianceReasons), not set
// to an empty array - "not yet checked/matched" and "checked, zero
// findings" are different states worth keeping distinct upstream, even
// though the UI's fallback message treats them the same way today.
export function applyDeviceComplianceReasons(
  devices: IntuneDevice[],
  reasonRows: { deviceName: string; reason: DeviceComplianceReason }[] | undefined
): IntuneDevice[] {
  if (!reasonRows || reasonRows.length === 0) return devices;

  const byDeviceName = new Map<string, DeviceComplianceReason[]>();
  for (const { deviceName, reason } of reasonRows) {
    const key = deviceName.toLowerCase();
    const existing = byDeviceName.get(key);
    if (existing) {
      existing.push(reason);
    } else {
      byDeviceName.set(key, [reason]);
    }
  }

  return devices.map((device) => {
    const reasons = byDeviceName.get(device.deviceName.toLowerCase());
    if (!reasons || reasons.length === 0) return device;
    return { ...device, nonComplianceReasons: reasons };
  });
}

// Maps a raw deviceManagement/mobileThreatDefenseConnectors entry (beta) into
// Clarity365's MdeConnectorSettings shape - a straight passthrough since
// Graph's own property names are already the toggle names, just documenting
// which ones are beta-only additions the v1.0 surface doesn't return.
export function mapMdeConnectorSettings(raw: any): MdeConnectorSettings {
  return {
    id: raw.id,
    lastHeartbeatDateTime: raw.lastHeartbeatDateTime || undefined,
    partnerState: raw.partnerState || "unavailable",
    microsoftDefenderForEndpointAttachEnabled: !!raw.microsoftDefenderForEndpointAttachEnabled,
    partnerUnsupportedOsVersionBlocked: !!raw.partnerUnsupportedOsVersionBlocked,
    androidEnabled: !!raw.androidEnabled,
    androidMobileApplicationManagementEnabled: !!raw.androidMobileApplicationManagementEnabled,
    androidDeviceBlockedOnMissingPartnerData: !!raw.androidDeviceBlockedOnMissingPartnerData,
    iosEnabled: !!raw.iosEnabled,
    iosMobileApplicationManagementEnabled: !!raw.iosMobileApplicationManagementEnabled,
    iosDeviceBlockedOnMissingPartnerData: !!raw.iosDeviceBlockedOnMissingPartnerData,
    allowPartnerToCollectIOSApplicationMetadata: !!raw.allowPartnerToCollectIOSApplicationMetadata,
    allowPartnerToCollectIOSPersonalApplicationMetadata: !!raw.allowPartnerToCollectIOSPersonalApplicationMetadata,
    allowPartnerToCollectIosCertificateMetadata: raw.allowPartnerToCollectIosCertificateMetadata,
    allowPartnerToCollectIosPersonalCertificateMetadata: raw.allowPartnerToCollectIosPersonalCertificateMetadata,
    windowsEnabled: !!raw.windowsEnabled,
    windowsMobileApplicationManagementEnabled: raw.windowsMobileApplicationManagementEnabled,
    windowsDeviceBlockedOnMissingPartnerData: !!raw.windowsDeviceBlockedOnMissingPartnerData,
    macEnabled: raw.macEnabled,
    macDeviceBlockedOnMissingPartnerData: raw.macDeviceBlockedOnMissingPartnerData,
  };
}

// Maps a raw advancedThreatProtectionOnboardingDeviceSettingState entry
// (beta) into Clarity365's AtpOnboardingDeviceState shape.
export function mapAtpOnboardingDeviceState(raw: any): AtpOnboardingDeviceState {
  return {
    deviceName: raw.deviceName || "",
    userPrincipalName: raw.userPrincipalName || undefined,
    platformType: raw.platformType || undefined,
    state: raw.state || "unknown",
  };
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
