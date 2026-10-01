// Pulled out for the same reason asr-configuration-mapper.ts and
// sign-in-country.ts were: this is a pure, unit-testable rule, kept separate
// from graph-client.ts's actual network calls.
//
// A missing Graph API permission and a missing license SKU can both come
// back from Graph as the identical generic 403 Authorization_RequestDenied /
// "Insufficient privileges to complete the operation" - verified directly,
// there is no reliable universal text signal to tell them apart. So this
// doesn't try to parse Graph's error message; it cross-checks the tenant's
// actual purchased capabilities (already computed by capabilities-mapper.ts
// from /subscribedSkus) against a small, explicit list of the permissions
// genuinely known to need a specific license underneath the Graph scope
// itself - not permission-consent-string-guessing.
import { TenantCapability } from "../types";
import type { PermissionTestResult } from "./graph-client";

export interface PermissionLicenseRequirement {
  capabilityId: string;
  friendlyName: string;
}

// Only the permissions with a genuinely known license dependency belong
// here - most of the app's tested permissions (Policy.Read.All,
// User.Read.All, AuditLog.Read.All, Group.Read.All, Sites.Read.All, etc.)
// work on any base M365 tenant with no extra SKU required, so they're
// deliberately absent.
export const PERMISSION_LICENSE_REQUIREMENT: Record<string, PermissionLicenseRequirement> = {
  "DeviceManagementManagedDevices.Read.All": { capabilityId: "cap-intune", friendlyName: "Microsoft Intune" },
  "DeviceManagementConfiguration.Read.All": { capabilityId: "cap-intune", friendlyName: "Microsoft Intune" },
  "DeviceManagementServiceConfig.Read.All": { capabilityId: "cap-intune", friendlyName: "Microsoft Intune" },
  "ThreatHunting.Read.All": {
    capabilityId: "cap-mde",
    friendlyName: "Defender for Endpoint P2 (or Business Premium's Defender for Business)",
  },
  "SecurityAlert.Read.All": { capabilityId: "cap-mdo", friendlyName: "Defender for Office 365" },
};

// Re-labels a failed permission test as "unlicensed" (rather than "missing")
// when the tenant is verifiably not licensed for the capability that
// permission depends on. Leaves every other result untouched - granted
// results, permissions with no known license dependency, and permissions
// that failed for a reason unrelated to licensing (the capability check
// comes back licensed: true) all pass through exactly as given.
export function applyLicenseAwareStatus(
  result: PermissionTestResult,
  capabilities: TenantCapability[]
): PermissionTestResult {
  if (result.status !== "missing") return result;

  const requirement = PERMISSION_LICENSE_REQUIREMENT[result.permission];
  if (!requirement) return result;

  const capability = capabilities.find((c) => c.id === requirement.capabilityId);
  if (!capability || capability.licensed) return result;

  return {
    ...result,
    status: "unlicensed",
    unlicensed: true,
    errorMessage: `This tenant does not have a ${requirement.friendlyName} license - granting this Graph API permission will not fix this.`,
  };
}
