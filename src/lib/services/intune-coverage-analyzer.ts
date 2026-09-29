// Two coverage-gap lenses over data the snapshot already has (plus the new
// per-device MDE onboarding telemetry) - "who's missing from Intune" and
// "what's enrolled but not protected." Pure functions, no fetching, so
// they're testable with hand-built fixtures and reusable from any module.
import { TenantAccountSummary, IntuneDevice, IntuneCoverageGapUser, IntuneCoverageGaps } from "../types";
import { isIntuneCapableSkuPartNumber } from "./capabilities-mapper";

export function findUsersMissingIntuneDevice(
  users: TenantAccountSummary["users"],
  devices: IntuneDevice[]
): IntuneCoverageGapUser[] {
  const enrolledUpns = new Set(devices.map((d) => d.userPrincipalName.toLowerCase()).filter(Boolean));

  return users
    .filter((u) => u.classification === "licensed" && u.accountEnabled)
    // A licensed user's own SKU may still not include Intune at all (e.g.
    // Exchange Online Kiosk) - flagging them as "missing from Intune" isn't a
    // closable gap, it's a false positive. Uses the same live-verified SKU
    // list capabilities-mapper.ts already applies tenant-wide, just per-user.
    .filter((u) => isIntuneCapableSkuPartNumber(u.licenses))
    .filter((u) => !enrolledUpns.has(u.userPrincipalName.toLowerCase()))
    .map((u) => ({
      userId: u.id,
      userPrincipalName: u.userPrincipalName,
      displayName: u.displayName,
      department: u.department,
    }));
}

// "unsupported" is deliberately excluded - a platform/OS version MDE simply
// can't onboard isn't a gap you can close, so flagging it as one would be
// noise, not an actionable finding.
export function findDevicesMissingEdr(devices: IntuneDevice[]): IntuneDevice[] {
  return devices.filter((d) => d.edrOnboardingState !== "onboarded" && d.edrOnboardingState !== "unsupported");
}

export function computeIntuneCoverageGaps(
  users: TenantAccountSummary["users"],
  devices: IntuneDevice[]
): IntuneCoverageGaps {
  return {
    usersWithoutIntuneDevice: findUsersMissingIntuneDevice(users, devices),
    devicesWithoutEdr: findDevicesMissingEdr(devices),
  };
}
